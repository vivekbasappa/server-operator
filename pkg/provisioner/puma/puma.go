package puma

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	//"os"
	//"sigs.k8s.io/yaml"
	//"sort"
	//"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"

	appv1alpha1 "github.com/example-inc/server-operator/pkg/apis/app/v1alpha1"
	"github.com/example-inc/server-operator/pkg/bmc"
	//"github.com/example-inc/server-operator/pkg/hardware"
	"github.com/example-inc/server-operator/pkg/provisioner"
	"github.com/example-inc/server-operator/pkg/pumas"
)

var log = logf.Log.WithName("puma_server")
var deprovisionRequeueDelay = time.Second * 10
var provisionRequeueDelay = time.Second * 600
var powerRequeueDelay = time.Second * 10
var introspectionRequeueDelay = time.Second * 15
var pumaEndpoint string
var inspectorEndpoint string

const (
	// See nodes.Node.PowerState for details
	powerOn   = "s5: Soft off"
	powerOff  = "power: working"
	powerNone = "None"
)

func init() {
	// NOTE(dhellmann): Use Fprintf() to report errors instead of
	// logging, because logging is not configured yet in init().
}

// Provisioner implements the provisioning.Provisioner interface
// and uses Puma to manage the host.
type pumaProvisioner struct {
	// the host to be managed by this provisioner
	host *appv1alpha1.Server
	// credentials to log in to the BMC
	pumaCreds pumas.Credentials
	// credentials to log in to the BMC
	bmcCreds bmc.Credentials
	// a client for talking to puma
	client *resty.Client
	// a client for talking to puma-inspector
	inspector *resty.Client
	// a logger configured for this host
	log logr.Logger
	// an event publisher for recording significant events
	publisher provisioner.EventPublisher
	// a shorter path to the provisioning status data structure
	status *appv1alpha1.ProvisionStatus
}

// LogStartup produces useful logging information that we only want to
// emit once on startup but that is interal to this package.
func LogStartup() {
	log.Info("puma settings",
		"endpoint", pumaEndpoint,
		"inspectorEndpoint", inspectorEndpoint,
	)
}

// A private function to construct an pumaProvisioner (rather than a
// Provisioner interface) in a consistent way for tests.
func newProvisioner(host *appv1alpha1.Server, pumaCreds pumas.Credentials, bmcCreds bmc.Credentials, publisher provisioner.EventPublisher) (*pumaProvisioner, error) {
	client := resty.New()
	client.SetDebug(true)
	//host.Spec.Puma.disablecertificateverification
	//client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	client.SetHostURL(host.Spec.Puma.Address)
	client.SetHeaders(map[string]string{
		"accept":       "application/json",
		"content-type": "application/json",
	})

	inspector := resty.New()
	inspector.SetDebug(true)
	//host.Spec.Puma.disablecertificateverification
	//inspector.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	inspector.SetHostURL(host.Spec.Puma.Address)
	inspector.SetHeaders(map[string]string{
		"accept":       "application/json",
		"content-type": "application/json",
	})

	// Ensure we have a microversion high enough to get the features
	// we need.
	p := &pumaProvisioner{
		host:      host,
		status:    &(host.Status.Provisioning),
		pumaCreds: pumaCreds,
		bmcCreds:  bmcCreds,
		client:    client,
		inspector: inspector,
		log:       log.WithValues("host", host.Name),
		publisher: publisher,
	}
	return p, nil
}

// New returns a new Puma Provisioner
func New(host *appv1alpha1.Server, pumaCreds pumas.Credentials, bmcCreds bmc.Credentials, publisher provisioner.EventPublisher) (provisioner.Provisioner, error) {
	return newProvisioner(host, pumaCreds, bmcCreds, publisher)
}

// Look for an existing registration for the host in Puma.
func (p *pumaProvisioner) findExistingHost() (pumaNode *appv1alpha1.ServerInfo, err error) {
	// Try to load the node by UUID
	pumaNode = new(appv1alpha1.ServerInfo)
	if p.status.ID != "" {
		// Look for the node to see if it exists (maybe Puma was
		// restarted)
		type ServerInfoNode struct {
			Server appv1alpha1.ServerInfo `json:"server"`
		}
		var serverInfoNode ServerInfoNode
		fmt.Println("LOG status ID: " + p.status.ID)
		url := fmt.Sprintf("/servers/%s", p.status.ID)
		//p.client = resty.New()
		p.client.SetHeader("X-Management-IPs", p.host.Spec.BMC.Address)
		p.client.SetHeader("X-Subsystem-User", p.bmcCreds.Username)
		p.client.SetHeader("X-Subsystem-Password", p.bmcCreds.Password)
		p.client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
		p.client.SetAllowGetMethodPayload(true)
		resp, err := p.client.R().Get(url)
		if resp.StatusCode() != 200 {
			fmt.Println("Puma failed with error: " + err.Error())
			return nil, errors.Wrap(err,
				fmt.Sprintf("failed to find server by ID %s", p.status.ID))

		}
		if err := json.Unmarshal(resp.Body(), &serverInfoNode); err != nil {
			fmt.Println("Client unmarshal failed: " + err.Error())
			return nil, errors.Wrap(err,
				fmt.Sprintf("failed to find server by ID %s", p.status.ID))
		}
		p.log.Info("found existing server by ID")
		*pumaNode = appv1alpha1.ServerInfo(serverInfoNode.Server)
		p.status.ID = pumaNode.ObjectId
		fmt.Printf("fmt %v\n", pumaNode)
		return pumaNode, nil
	}

	var pumaNodes appv1alpha1.ServerInfos
	// Try to load the node by name
	p.log.Info("looking for existing node by name", "name", p.host.Name)
	serverDetails := fmt.Sprintf(`{ "logins" : [{"ip": "%s", "userName": "%s", "password": "%s" }]}`,
		p.host.Spec.BMC.Address, p.bmcCreds.Username, p.bmcCreds.Password)
	url := fmt.Sprintf("/servers")
	p.client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	p.client.SetAllowGetMethodPayload(true)
	resp, err := p.client.R().
		SetBody(serverDetails).
		Get(url)
	p.log.Info("printing", "response", resp.Body())
	if resp.StatusCode() != 200 {
		fmt.Println("Client unmarshal failed: " + err.Error())
		return nil, errors.Wrap(err,
			fmt.Sprintf("failed to find server info for ID %s", p.status.ID))

	}
	if err = json.Unmarshal(resp.Body(), &pumaNodes); err != nil {
		fmt.Println("Client unmarshal failed: " + err.Error())
		return nil, errors.Wrap(err,
			fmt.Sprintf("failed to find server info for ID %s", p.status.ID))
	}
	p.log.Info("found existing node by ID")
	*pumaNode = appv1alpha1.ServerInfo(pumaNodes.Servers[0])
	//pumaNode = &pumaNodes.Server
	p.status.ID = pumaNode.ObjectId
	fmt.Printf("fmt %v\n", pumaNode)
	return pumaNode, nil
}

// ValidateManagementAccess registers the host with the provisioning
// system and tests the connection information for the host to verify
// that the location and credentials work.
//
func (p *pumaProvisioner) ValidateManagementAccess(credentialsChanged bool) (result provisioner.Result, err error) {

	var pumaNode *appv1alpha1.ServerInfo
	var pumaNodes appv1alpha1.ServerInfos

	p.log.Info("validating management access")

	pumaNode, err = p.findExistingHost()
	if err != nil {
		return result, errors.Wrap(err, "failed to find existing host")
	}

	if pumaNode == nil {
		pumaNode = new(appv1alpha1.ServerInfo)
		// Try to load the node by name
		p.log.Info("looking for existing node by name", "name", p.host.Name)
		serverDetails := fmt.Sprintf(`{ "logins" : [{"ip": "%s", "userName": "%s", "password": "%s" }]}`, p.host.Spec.BMC.Address, p.bmcCreds.Username, p.bmcCreds.Password)
		url := fmt.Sprintf("/servers")
		p.client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
		p.client.SetAllowGetMethodPayload(true)
		resp, err := p.client.R().
			SetBody(serverDetails).
			Get(url)
		if resp.StatusCode() != 200 {
			fmt.Println("Client unmarshal failed: " + err.Error())
			result.ErrorMessage = err.Error()
			result.Dirty = true
			return result, errors.Wrap(err, "failed to register the host to puma")

		}
		if err := json.Unmarshal(resp.Body(), &pumaNodes); err != nil {
			fmt.Println("Client unmarshal failed: " + err.Error())
			result.ErrorMessage = err.Error()
			result.Dirty = true
			return result, errors.Wrap(err, "failed to register the host to puma, uknown error while parsing")
		}
		p.log.Info("puma server info", "Discovery", pumaNodes)
		p.publisher("Registered", "Registered new host")
		//copy(pumaNode, pumaNodes.Server)
		*pumaNode = appv1alpha1.ServerInfo(pumaNodes.Servers[0])
		p.status.ID = pumaNode.ObjectId
		result.Dirty = false
		p.log.Info("setting provisioning id", "ID", p.status.ID)
		return result, nil
	} else {
		// puma objectID can change,if they restart the puma service
		// At this point we have found an existing
		// server in puma by looking it up. We need to check its
		// settings against what we have in the host, and change them
		// if there are differences.
		if p.status.ID != pumaNode.ObjectId {
			// Store the ID so other methods can assume it is set and
			// so we can find the server using that value next time.
			p.status.ID = pumaNode.ObjectId
			result.Dirty = true
			p.log.Info("setting provisioning id", "ID", p.status.ID)
			result.Dirty = true
			return result, nil
		}
		result.Dirty = false
		result.RequeueAfter = provisionRequeueDelay
		return result, nil

	}
}

func (p *pumaProvisioner) getBMCDetails() appv1alpha1.BMCDetails {
	type BMCNode struct {
		BMC appv1alpha1.BMCDetails `json:"BMC,omitempty"`
	}
	var bmcDetails appv1alpha1.BMCDetails
	var bmcDetailsNode BMCNode

	url := fmt.Sprintf("%s/servers/%s/bmc",
		p.host.Spec.Puma.Address, p.status.ID)
	p.client = resty.New()
	p.client.SetDebug(true)
	//host.Spec.Puma.disablecertificateverification
	p.client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	p.client.SetHostURL(p.host.Spec.Puma.Address)
	p.client.SetHeaders(map[string]string{
		"accept":       "application/json",
		"content-type": "application/json",
	})
	p.client.SetHeader("X-Management-IPs", p.host.Spec.BMC.Address)
	p.client.SetHeader("X-Subsystem-User", p.bmcCreds.Username)
	p.client.SetHeader("X-Subsystem-Password", p.bmcCreds.Password)

	resp, err := p.client.R().Get(url)
	if resp.StatusCode() != 200 {
		fmt.Println("Client unmarshal failed: " + err.Error())
		//return nil, errors.Wrap(err, "failed to register the host to puma")
		return appv1alpha1.BMCDetails{}
	}
	if err := json.Unmarshal(resp.Body(), &bmcDetailsNode); err != nil {
		fmt.Println("Client unmarshal failed: " + err.Error())
		return appv1alpha1.BMCDetails{}
	}
	bmcDetails = appv1alpha1.BMCDetails(bmcDetailsNode.BMC)
	return bmcDetails
}

func (p *pumaProvisioner) setCPuPowerState() {
}

func (p *pumaProvisioner) getCPuPowerState() {
}

func (p *pumaProvisioner) powerOn() (result provisioner.Result, err error) {
	url := fmt.Sprintf("%s/servers/%s/power-on", p.host.Spec.Puma.Address, p.status.ID)
	powerjson := fmt.Sprintf(`{"X-Subsystem-User": "%s", "X-Subsystem-Password" : "%s", "X-Management-IPs": "", "id": "%s" }`,
		p.bmcCreds.Username, p.bmcCreds.Password, p.host.Spec.BMC.Address)
	p.client = resty.New()
	p.client.SetDebug(true)
	//host.Spec.Puma.disablecertificateverification
	p.client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	p.client.SetHostURL(p.host.Spec.Puma.Address)
	p.client.SetHeaders(map[string]string{
		"accept":       "application/json",
		"content-type": "application/json",
	})

	var powerState appv1alpha1.Power
	resp, err := p.client.R().SetBody(powerjson).Post(url)
	if resp.StatusCode() != 200 {
		fmt.Println("Client unmarshal failed: " + err.Error())
		result.ErrorMessage = err.Error()
		result.Dirty = true
		return result, errors.Wrap(err, "failed to register the host to puma")

	}

	if err := json.Unmarshal(resp.Body(), powerState); err != nil {
		fmt.Println("Client unmarshal failed: " + err.Error())
		result.ErrorMessage = err.Error()
		result.Dirty = true
		return result, errors.Wrap(err, "failed to register the host to puma, unknown error while parsing")
	}
	result.Dirty = true
	return result, nil
}

func (p *pumaProvisioner) powerOff() (result provisioner.Result, err error) {

	url := fmt.Sprintf("%s/servers/%s/power-on", p.host.Spec.Puma.Address, p.status.ID)
	powerjson := fmt.Sprintf(`{"X-Subsystem-User": "%s", "X-Subsystem-Password" : "%s", "X-Management-IPs": "", "id": "%s" }`,
		p.bmcCreds.Username, p.bmcCreds.Password, p.host.Spec.BMC.Address)
	p.client = resty.New()
	p.client.SetDebug(true)
	//host.Spec.Puma.disablecertificateverification
	p.client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	p.client.SetHostURL(p.host.Spec.Puma.Address)
	p.client.SetHeaders(map[string]string{
		"accept":       "application/json",
		"content-type": "application/json",
	})

	var powerState appv1alpha1.Power
	resp, err := p.client.R().SetBody(powerjson).Post(url)
	if resp.StatusCode() != 200 {
		fmt.Println("Client unmarshal failed: " + err.Error())
		result.ErrorMessage = err.Error()
		result.Dirty = true
		return result, errors.Wrap(err, "failed to register the host to puma")

	}

	if err := json.Unmarshal(resp.Body(), powerState); err != nil {
		fmt.Println("Client unmarshal failed: " + err.Error())
		result.ErrorMessage = err.Error()
		result.Dirty = true
		return result, errors.Wrap(err, "failed to register the host to puma, unknown error while parsing")
	}
	result.Dirty = true
	return result, nil

}

func (p *pumaProvisioner) getServer() appv1alpha1.ServerInfo {
	var serverinfo appv1alpha1.ServerInfo
	type ServerInfoNode struct {
		Server appv1alpha1.ServerInfo `json:"server"`
	}
	var serverInfoNode ServerInfoNode
	fmt.Println("LOG status ID: " + p.status.ID)
	url := fmt.Sprintf("/servers/%s", p.status.ID)
	//p.client = resty.New()
	p.client.SetHeader("X-Management-IPs", p.host.Spec.BMC.Address)
	p.client.SetHeader("X-Subsystem-User", p.bmcCreds.Username)
	p.client.SetHeader("X-Subsystem-Password", p.bmcCreds.Password)
	p.client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	p.client.SetAllowGetMethodPayload(true)
	resp, err := p.client.R().Get(url)
	if resp.StatusCode() != 200 {
		fmt.Println("error while get server called ", err.Error())
		return appv1alpha1.ServerInfo{}

	}
	if err := json.Unmarshal(resp.Body(), &serverInfoNode); err != nil {
		fmt.Println("error while get server called ", err.Error())
		return appv1alpha1.ServerInfo{}
	}
	p.log.Info("found existing server by ID")
	serverinfo = appv1alpha1.ServerInfo(serverInfoNode.Server)
	return serverinfo

}

func (p *pumaProvisioner) powerCycle() {
}
func (p *pumaProvisioner) getDeviceID() {
}

func (p *pumaProvisioner) getAllFRUs() {
}

func (p *pumaProvisioner) getEthernetInfo() {
}

func (p *pumaProvisioner) getSystemEvents() {
}

func (p *pumaProvisioner) getAuditLog() {
}
func (p *pumaProvisioner) clearSystemEventLog() {
}

func (p *pumaProvisioner) removeSystemLogConfiguration() {
}

func (p *pumaProvisioner) setBootOption() {
}

func (p *pumaProvisioner) resetServerBootOption() {
}

func (p *pumaProvisioner) resetServerBMC() {
}

func (p *pumaProvisioner) resetBMCPassword() {
}

func (p *pumaProvisioner) getNICDetails() appv1alpha1.Network {
	var network appv1alpha1.Network
	type NetworkNode struct {
		Network appv1alpha1.Network `json:"network"`
	}
	var networkNode NetworkNode
	url := fmt.Sprintf("/servers/%s/network", p.status.ID)
	//p.client = resty.New()
	p.client.SetHeader("X-Management-IPs", p.host.Spec.BMC.Address)
	p.client.SetHeader("X-Subsystem-User", p.bmcCreds.Username)
	p.client.SetHeader("X-Subsystem-Password", p.bmcCreds.Password)
	p.client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	p.client.SetAllowGetMethodPayload(true)
	resp, err := p.client.R().Get(url)
	if resp.StatusCode() != 200 {
		fmt.Println("error while get server called ", err.Error())
		return appv1alpha1.Network{}

	}
	if err := json.Unmarshal(resp.Body(), &networkNode); err != nil {
		fmt.Println("error while get network called ", err.Error())
		return appv1alpha1.Network{}
	}
	p.log.Info("get network details success")
	network = appv1alpha1.Network(networkNode.Network)
	return network

}

func (p *pumaProvisioner) getCPUDetails() []appv1alpha1.CPU {
	type CPUNode struct {
		CPU appv1alpha1.Network `json:"network"`
	}
	var networkNode NetworkNode
	url := fmt.Sprintf("/servers/%s/network", p.status.ID)
	//p.client = resty.New()
	p.client.SetHeader("X-Management-IPs", p.host.Spec.BMC.Address)
	p.client.SetHeader("X-Subsystem-User", p.bmcCreds.Username)
	p.client.SetHeader("X-Subsystem-Password", p.bmcCreds.Password)
	p.client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	p.client.SetAllowGetMethodPayload(true)
	resp, err := p.client.R().Get(url)
	if resp.StatusCode() != 200 {
		fmt.Println("error while get server called ", err.Error())
		return appv1alpha1.Network{}
	}
	if err := json.Unmarshal(resp.Body(), &networkNode); err != nil {
		fmt.Println("error while get network called ", err.Error())
		return appv1alpha1.Network{}
	}
	p.log.Info("get network details success")
	network = appv1alpha1.Network(networkNode.Network)
	return network
}

func (p *pumaProvisioner) getHardwareDetails() *appv1alpha1.HardwareDetails {
	//var err error
	details := new(appv1alpha1.HardwareDetails)
	details.BMC = p.getBMCDetails()
	//details.Firmware = getFirmwareDetails(data.Extra.Firmware)
	//details.SystemVendor = getSystemVendorDetails(data.Inventory.SystemVendor)
	//details.RAMMebibytes = data.MemoryMB
	details.NIC = getNICDetails(data.Inventory.Interfaces, data.AllInterfaces, data.Extra.Network)
	//details.Storage = getStorageDetails(data.Inventory.Disks)
	details.CPU = getCPUDetails(&data.Inventory.CPU)
	//details.Hostname = data.Inventory.Hostname
	return details
}

// InspectHardware updates the HardwareDetails field of the host with
// details of devices discovered on the hardware. It may be called
// multiple times, and should return true for its dirty flag until the
// inspection is completed.
func (p *pumaProvisioner) InspectHardware() (result provisioner.Result, details *appv1alpha1.HardwareDetails, err error) {
	p.log.Info("inspecting hardware", "status", p.host.OperationalStatus())

	pumaNode, err := p.findExistingHost()
	if err != nil {
		err = errors.Wrap(err, "failed to find existing host")
		return
	}
	if pumaNode == nil {
		return result, nil, fmt.Errorf("no puma node for host")
	}

	details = p.getHardwareDetails()
	p.publisher("InspectionComplete", "Hardware inspection completed")
	return
}

// UpdateHardwareState fetches the latest hardware state of the server
// and updates the HardwareDetails field of the host with details. It
// is expected to do this in the least expensive way possible, such as
// reading from a cache, and return dirty only if any state
// information has changed.
func (p *pumaProvisioner) UpdateHardwareState() (result provisioner.Result, err error) {
	p.log.Info("updating hardware state")

	pumaNode, err := p.findExistingHost()
	if err != nil {
		return result, errors.Wrap(err, "failed to find existing host")
	}
	if pumaNode == nil {
		return result, fmt.Errorf("no puma node for host")
	}

	url := fmt.Sprintf("%s/servers/%s/system-power-state", p.host.Spec.Puma.Address, p.status.ID)
	p.client = resty.New()
	p.client.SetDebug(true)
	//host.Spec.Puma.disablecertificateverification
	p.client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	p.client.SetHostURL(p.host.Spec.Puma.Address)
	p.client.SetHeaders(map[string]string{
		"accept":       "application/json",
		"content-type": "application/json",
	})

	var powerState appv1alpha1.Power
	resp, err := p.client.R().Get(url)
	if resp.StatusCode() != 200 {
		fmt.Println("Client unmarshal failed: " + err.Error())
		result.ErrorMessage = err.Error()
		result.Dirty = true
		return result, errors.Wrap(err, "failed to register the host to puma")

	}

	if err := json.Unmarshal(resp.Body(), powerState); err != nil {
		fmt.Println("Client unmarshal failed: " + err.Error())
		result.ErrorMessage = err.Error()
		result.Dirty = true
		return result, errors.Wrap(err, "failed to register the host to puma, unknown error while parsing")
	}
	var discoveredVal bool

	switch powerState.PowerState {
	case powerOn:
		discoveredVal = true
	case powerOff:
		discoveredVal = false
	case powerNone:
		p.log.Info("could not determine power state", "value", pumaNode.PowerState)
		return result, nil
	default:
		p.log.Info("unknown power state", "value", pumaNode.PowerState)
		return result, nil
	}

	if discoveredVal != p.host.Status.PoweredOn {
		p.log.Info("updating power status", "discovered", discoveredVal)
		p.host.Status.PoweredOn = discoveredVal
		result.Dirty = true
	}
	return result, nil
}

func (p *pumaProvisioner) changePower(targetPowerState string) (result provisioner.Result, err error) {
	p.log.Info("changing power state")

	url := fmt.Sprintf("%s/servers/%s/system-power-state", p.host.Spec.Puma.Address, p.status.ID)
	p.client = resty.New()
	p.client.SetDebug(true)
	//host.Spec.Puma.disablecertificateverification
	p.client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	p.client.SetHostURL(p.host.Spec.Puma.Address)
	p.client.SetHeaders(map[string]string{
		"accept":       "application/json",
		"content-type": "application/json",
	})

	var powerState appv1alpha1.Power
	resp, err := p.client.R().Get(url)

	if resp.StatusCode() != 200 {
		fmt.Println("Client unmarshal failed: " + err.Error())
		result.ErrorMessage = err.Error()
		result.Dirty = true
		return result, errors.Wrap(err, "failed to register the host to puma")

	}

	if err := json.Unmarshal(resp.Body(), powerState); err != nil {
		fmt.Println("Client unmarshal failed: " + err.Error())
		result.ErrorMessage = err.Error()
		result.Dirty = true
		return result, errors.Wrap(err, "failed to register the host to puma, unknown error while parsing")
	}

	switch powerState.PowerState {
	case powerOff:
		if targetPowerState != powerState.PowerState {
			result, err := p.powerOn()
			return result, err
		} else {
			result.Dirty = true
			return result, nil
		}
		break
	case powerOn:
		if targetPowerState != powerState.PowerState {
			result, err := p.PowerOff()
			return result, err
		} else {
			result.Dirty = true
			return result, nil
		}
		break
	default:
		result.Dirty = true
		return result, nil
	}

	result.Dirty = true
	p.log.Info("power change OK")
	return result, nil
}

// PowerOn ensures the server is powered on independently of any image
// provisioning operation.
func (p *pumaProvisioner) PowerOn() (result provisioner.Result, err error) {
	p.log.Info("ensuring host is powered on")

	pumaNode, err := p.findExistingHost()
	if err != nil {
		return result, errors.Wrap(err, "failed to find existing host")
	}

	p.log.Info("checking current state",
		"current", p.host.Status.PoweredOn,
		"target", pumaNode.TargetPowerState)

	if pumaNode.PowerState.PowerState != powerOn {
		if pumaNode.TargetPowerState == powerOn {
			p.log.Info("waiting for power status to change")
			result.RequeueAfter = powerRequeueDelay
			result.Dirty = true
			return result, nil
		}
		result, err = p.changePower(powerOn)
		if err != nil {
			result.RequeueAfter = powerRequeueDelay
			return result, errors.Wrap(err, "failed to power on host")
		}
		p.publisher("PowerOn", "Host powered on")
	}

	return result, nil
}

// PowerOff ensures the server is powered off independently of any image
// provisioning operation.
func (p *pumaProvisioner) PowerOff() (result provisioner.Result, err error) {
	p.log.Info("ensuring host is powered off")

	pumaNode, err := p.findExistingHost()
	if err != nil {
		return result, errors.Wrap(err, "failed to find existing host")
	}

	if pumaNode.PowerState.PowerState != powerOff {
		if pumaNode.TargetPowerState == powerOff {
			p.log.Info("waiting for power status to change")
			result.RequeueAfter = powerRequeueDelay
			result.Dirty = true
			return result, nil
		}
		result, err = p.changePower(powerOff)
		if err != nil {
			result.RequeueAfter = powerRequeueDelay
			return result, errors.Wrap(err, "failed to power off host")
		}
		p.publisher("PowerOff", "Host powered off")
	}

	return result, nil
}
