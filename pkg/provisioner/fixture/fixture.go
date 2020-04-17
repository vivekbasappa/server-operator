package fixture

import (
	"time"

	"github.com/go-logr/logr"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"

	appv1alpha1 "github.com/example-inc/server-operator/pkg/apis/app/v1alpha1"
	"github.com/example-inc/server-operator/pkg/bmc"
	"github.com/example-inc/server-operator/pkg/provisioner"
	"github.com/example-inc/server-operator/pkg/pumas"
)

var log = logf.Log.WithName("fixture")
var deprovisionRequeueDelay = time.Second * 10
var provisionRequeueDelay = time.Second * 10

// Provisioner implements the provisioning.Provisioner interface
// and uses Ironic to manage the host.
type fixtureProvisioner struct {
	// the host to be managed by this provisioner
	host *appv1alpha1.Server
	// the bmc credentials
	pumaCreds pumas.Credentials
	// the bmc credentials
	bmcCreds bmc.Credentials
	// a logger configured for this host
	log logr.Logger
	// an event publisher for recording significant events
	publisher provisioner.EventPublisher
	// state to manage the two-step adopt process
	adopted bool
}

// New returns a new Ironic Provisioner
func New(host *appv1alpha1.Server, pumaCreds pumas.Credentials, bmcCreds bmc.Credentials, publisher provisioner.EventPublisher) (provisioner.Provisioner, error) {
	p := &fixtureProvisioner{
		host:      host,
		pumaCreds: pumaCreds,
		bmcCreds:  bmcCreds,
		log:       log.WithValues("host", host.Name),
		publisher: publisher,
	}
	return p, nil
}

// ValidateManagementAccess tests the connection information for the
// host to verify that the location and credentials work.
func (p *fixtureProvisioner) ValidateManagementAccess(credentialsChanged bool) (result provisioner.Result, err error) {
	p.log.Info("testing management access")

	// Fill in the ID of the host in the provisioning system
	if p.host.Status.Provisioning.ID == "" {
		p.host.Status.Provisioning.ID = "temporary-fake-id"
		p.log.Info("setting provisioning id",
			"provisioningID", p.host.Status.Provisioning.ID)
		result.Dirty = true
		result.RequeueAfter = time.Second * 5
		p.publisher("Registered", "Registered new host")
		return result, nil
	}

	return result, nil
}

// InspectHardware updates the HardwareDetails field of the host with
// details of devices discovered on the hardware. It may be called
// multiple times, and should return true for its dirty flag until the
// inspection is completed.
func (p *fixtureProvisioner) InspectHardware() (result provisioner.Result, details *appv1alpha1.HardwareDetails, err error) {
	p.log.Info("inspecting hardware", "status", p.host.OperationalStatus())

	// The inspection is ongoing. We'll need to check the fixture
	// status for the server here until it is ready for us to get the
	// inspection details. Simulate that for now by creating the
	// hardware details struct as part of a second pass.
	if p.host.Status.HardwareDetails == nil {
		p.log.Info("continuing inspection by setting details")
		details =
			&appv1alpha1.HardwareDetails{
				NIC: appv1alpha1.Network{
					HostName: "test1.sie.hitachi.com",
					NetworkInterfaces: []appv1alpha1.NIC{
						appv1alpha1.NIC{
							Name:      "nic-1",
							Model:     "virt-io",
							MAC:       "some:mac:address",
							IP:        "192.168.100.1",
							SpeedGbps: 1,
						},
						appv1alpha1.NIC{
							Name:      "nic-2",
							Model:     "e1000",
							MAC:       "some:other:mac:address",
							IP:        "192.168.100.2",
							SpeedGbps: 1,
						},
					},
				},
				CPU: []appv1alpha1.CPU{
					appv1alpha1.CPU{
						Slot:      1,
						Speed:     "100x",
						Vendor:    "Intel",
						IsPresent: true,
						Thread:    "thread1",
						Cores:     1,
					},
					appv1alpha1.CPU{
						Slot:      2,
						Speed:     "100x",
						Vendor:    "Intel",
						IsPresent: true,
						Thread:    "thread1",
						Cores:     1,
					},
				},
			}
		p.publisher("InspectionComplete", "Hardware inspection completed")
	}

	return
}

// UpdateHardwareState fetches the latest hardware state of the server
// and updates the HardwareDetails field of the host with details. It
// is expected to do this in the least expensive way possible, such as
// reading from a cache, and return dirty only if any state
// information has changed.
func (p *fixtureProvisioner) UpdateHardwareState() (result provisioner.Result, err error) {
	if !p.host.NeedsProvisioning() {
		p.log.Info("updating hardware state")
		result.Dirty = false
	}
	return result, nil
}

// Adopt allows an externally-provisioned server to be adopted.
func (p *fixtureProvisioner) Adopt() (result provisioner.Result, err error) {
	p.log.Info("adopting host")
	return
}

// Provision writes the image from the host spec to the host. It may
// be called multiple times, and should return true for its dirty flag
// until the deprovisioning operation is completed.
func (p *fixtureProvisioner) Provision(hostConf provisioner.HostConfigData) (result provisioner.Result, err error) {
	p.log.Info("provisioning image to host",
		"state", p.host.Status.Provisioning.State)
	return result, nil
}

// Deprovision removes the host from the image. It may be called
// multiple times, and should return true for its dirty flag until the
// deprovisioning operation is completed.
func (p *fixtureProvisioner) Deprovision() (result provisioner.Result, err error) {
	p.log.Info("ensuring host is deprovisioned")

	result.RequeueAfter = deprovisionRequeueDelay

	// NOTE(dhellmann): In order to simulate a multi-step process,
	// modify some of the status data structures. This is likely not
	// necessary once we really have Fixture doing the deprovisioning
	// and we can monitor it's status.

	if p.host.Status.HardwareDetails != nil {
		p.publisher("DeprovisionStarted", "Image deprovisioning started")
		p.log.Info("clearing hardware details")
		p.host.Status.HardwareDetails = nil
		result.Dirty = true
		return result, nil
	}

	p.publisher("DeprovisionComplete", "Image deprovisioning completed")
	return result, nil
}

// Delete removes the host from the provisioning system. It may be
// called multiple times, and should return true for its dirty flag
// until the deprovisioning operation is completed.
func (p *fixtureProvisioner) Delete() (result provisioner.Result, err error) {
	p.log.Info("deleting host")

	if p.host.Status.Provisioning.ID != "" {
		p.log.Info("clearing provisioning id")
		p.host.Status.Provisioning.ID = ""
		result.Dirty = true
		return result, nil
	}

	return result, nil
}

// PowerOn ensures the server is powered on independently of any image
// provisioning operation.
func (p *fixtureProvisioner) PowerOn() (result provisioner.Result, err error) {
	p.log.Info("ensuring host is powered on")

	if !p.host.Status.PoweredOn {
		p.publisher("PowerOn", "Host powered on")
		p.log.Info("changing status")
		p.host.Status.PoweredOn = true
		result.Dirty = true
		return result, nil
	}

	return result, nil
}

// PowerOff ensures the server is powered off independently of any image
// provisioning operation.
func (p *fixtureProvisioner) PowerOff() (result provisioner.Result, err error) {
	p.log.Info("ensuring host is powered off")

	if p.host.Status.PoweredOn {
		p.publisher("PowerOff", "Host powered off")
		p.log.Info("changing status")
		p.host.Status.PoweredOn = false
		result.Dirty = true
		return result, nil
	}

	return result, nil
}
