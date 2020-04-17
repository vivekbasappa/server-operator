package v1alpha1

import (
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// NOTE: json tags are required.  Any new fields you add must have
// json tags for the fields to be serialized.

// NOTE(dhellmann): Update docs/api.md when changing these data structure.

const (
	// ServerFinalizer is the name of the finalizer added to
	// hosts to block delete operations until the physical host can be
	// deprovisioned.
	ServerFinalizer string = "server.app.example.com"

	// PausedAnnotation is the annotation that pauses the reconciliation (triggers
	// an immediate requeue)
	PausedAnnotation = "server.app.example.com/paused"
)

// OperationalStatus represents the state of the host
type OperationalStatus string

const (
	// OperationalStatusOK is the status value for when the host is
	// configured correctly and is manageable.
	OperationalStatusOK OperationalStatus = "OK"

	// OperationalStatusDiscovered is the status value for when the
	// host is only partially configured, such as when when the BMC
	// address is known but the login credentials are not.
	OperationalStatusDiscovered OperationalStatus = "discovered"

	// OperationalStatusError is the status value for when the host
	// has any sort of error.
	OperationalStatusError OperationalStatus = "error"
)

// ErrorType indicates the class of problem that has caused the Host resource
// to enter an error state.
type ErrorType string

const (
	// RegistrationError is an error condition occurring when the
	// controller is unable to connect to the Host's baseboard management
	// controller.
	RegistrationError ErrorType = "registration error"
	// InspectionError is an error condition occurring when an attempt to
	// obtain hardware details from the Host fails.
	InspectionError ErrorType = "inspection error"
	// ProvisioningError is an error condition occuring when the controller
	// fails to provision or deprovision the Host.
	ProvisioningError ErrorType = "provisioning error"
	// PowerManagementError is an error condition occurring when the
	// controller is unable to modify the power state of the Host.
	PowerManagementError ErrorType = "power management error"
)

// ProvisioningState defines the states the provisioner will report
// the host has having.
type ProvisioningState string

const (
	// StateNone means the state is unknown
	StateNone ProvisioningState = ""

	// StateRegistrationError means there was an error registering the
	// host with the backend
	StateRegistrationError ProvisioningState = "registration error"

	// StateRegistering means we are telling the backend about the host
	StateRegistering ProvisioningState = "registering"

	// StateMatchProfile means we are comparing the discovered details
	// against known hardware profiles
	StateMatchProfile ProvisioningState = "match profile"

	// StateReady means the host can be consumed
	StateReady ProvisioningState = "ready"

	// StateAvailable means the host can be consumed
	StateAvailable ProvisioningState = "available"

	// StateInspecting means we are running the agent on the host to
	// learn about the hardware components available there
	StateInspecting ProvisioningState = "inspecting"

	// StatePowerManagementError means something went wrong trying to
	// power the server on or off.
	StatePowerManagementError ProvisioningState = "power management error"
)

// PumaDetails contains the information necessary to communicate with
// the bare metal controller module on host.
type PumaDetails struct {

	// Address holds the URL for accessing the controller on the
	// network.
	Address string `json:"address"`

	// The name of the secret containing the BMC credentials (requires
	// keys "username" and "password").
	CredentialsName string `json:"credentialsName"`

	// DisableCertificateVerification disables verification of server
	// certificates when using HTTPS to connect to the BMC. This is
	// required when the server certificate is self-signed, but is
	// insecure because it allows a man-in-the-middle to intercept the
	// connection.
	DisableCertificateVerification bool `json:"disableCertificateVerification,omitempty"`
}

// BMCDetails contains the information necessary to communicate with
// the bare metal controller module on host.
type BMCDetails struct {

	// Address holds the URL for accessing the controller on the
	// network.
	Address string `json:"address"`

	// The name of the secret containing the BMC credentials (requires
	// keys "username" and "password").
	CredentialsName string `json:"credentialsName"`

	LANChannel      string `json:"LANChannel,omitempty"`
	MAC             string `json:"MAC,omitempty"`
	ChannelAuthType string `json:"channelAuthType,omitempty"`
	ChipSet         string `json:"chipSet,omitempty"`
	DriveType       string `json:"driveType,omitempty"`
	Gateway         string `json:"gateway,omitempty"`
	IPAddressV4     string `json:"ipaddressV4,omitempty"`
	IPAddressV6     string `json:"ipaddressV6,omitempty"`
	Manufacturer    string `json:"manufacturer,omitempty"`
	NetworkMode     string `json:"networkMade,omitempty"`
	SelfTestStatus  string `json:"selfTestStatus,omitempty"`
	Version         string `json:"version,omitempty"`

	// DisableCertificateVerification disables verification of server
	// certificates when using HTTPS to connect to the BMC. This is
	// required when the server certificate is self-signed, but is
	// insecure because it allows a man-in-the-middle to intercept the
	// connection.
	DisableCertificateVerification bool `json:"disableCertificateVerification,omitempty"`
}

// ServerSpec defines the desired state of Server
type ServerSpec struct {
	// Important: Run "operator-sdk generate k8s" to regenerate code
	// after modifying this file

	// Taints is the full, authoritative list of taints to apply to
	// the corresponding Machine. This list will overwrite any
	// modifications made to the Machine on an ongoing basis.
	// +optional
	Taints []corev1.Taint `json:"taints,omitempty"`

	// How do we connect to the PUMA?
	Puma PumaDetails `json:"puma,omitempty"`

	// How do we connect to the BMC?
	BMC BMCDetails `json:"bmc,omitempty"`

	// What is the name of the hardware profile for this host? It
	// should only be necessary to set this when inspection cannot
	// automatically determine the profile.
	HardwareProfile string `json:"hardwareProfile,omitempty"`

	// Should the server be online?
	Online bool `json:"online"`

	// ConsumerRef can be used to store information about something
	// that is using a host. When it is not empty, the host is
	// considered "in use".
	ConsumerRef *corev1.ObjectReference `json:"consumerRef,omitempty"`

	// Description is a human-entered text used to help identify the host
	Description string `json:"description,omitempty"`
}

// User
type User struct {
	AuthLevel string `json:"authLevel"`
	IsEnabled string `json:"isEnabled"`
	Name      string `json:"name"`
	Number    string `json:"number"`
	Password  string `json:"password"`
}

// FIXME(dhellmann): We probably want some other module to own these
// data structures.

// ClockSpeed is a clock speed in MHz
type ClockSpeed float64

// ClockSpeed multipliers
const (
	MegaHertz ClockSpeed = 1.0
	GigaHertz            = 1000 * MegaHertz
)

// Capacity is a disk size in Bytes
type Capacity int64

// Capacity multipliers
const (
	Byte     Capacity = 1
	KibiByte          = Byte * 1024
	KiloByte          = Byte * 1000
	MebiByte          = KibiByte * 1024
	MegaByte          = KiloByte * 1000
	GibiByte          = MebiByte * 1024
	GigaByte          = MegaByte * 1000
	TebiByte          = GibiByte * 1024
	TeraByte          = GigaByte * 1000
)

//
type ServerInfo struct {
	BIOSversion      string `json:"BIOSVersion,omitempty"`
	BMCIPAddress     string `json:"BMCIPAddress"`
	FirmwareVersion  string `json:"firmwareVerion,omitempty"`
	Name             string `json:"name,omitempty"`
	Serial           string `json:"serial,omitempty"`
	BladeId          int    `json:"bladeId,omitempty"`
	Vendor           string `json:"vendor"`
	ObjectId         string `json:"objectId"`
	CPUs             []CPU  `json:"cpus,omitempty"`
	GPUs             []GPU  `json:"gpus,omitempty"`
	PowerState       Power  `json:"power,omitempty"`
	TargetPowerState string `json:"targetPowerState,omitempty"`
}

//
type ServerInfos struct {
	Servers []ServerInfo `json:"servers,omitempty"`
}

// FRU
type FRU struct {
	FRUId      int `json:"fruId"`
	Attributes int `json:"attributes"`
}

// CPU describes one processor on the host.
type CPU struct {
	Slot      int    `json:"slot"`
	Speed     string `json:"speed"`
	Vendor    string `json:"vendor"`
	IsPresent bool   `json:"isPresent"`
	Thread    string `json:"thread"`
	Cores     int    `json:"cores"`
}

// GPU describes one gpu on the host.
type GPU struct {
	Model  string `json:"model"`
	Vendor string `json:"vendor"`
}

// LED describes LED status  on the host.
type LED struct {
	Status string `json:"status"`
}

type AuditLog struct {
	Time    string `json:"time"`
	EventId int    `json:"eventId"`
	Host    string `json:"host"`
	Message string `json:"message"`
}

type SystemEvent struct {
	DateTime     string   `json:"dateTime"`
	Detail       []string `json:"detail"`
	EventId      int      `json:"eventId"`
	Sensor       string   `json:"sensor"`
	SensorNumber int      `json:"sensorNumber"`
	Severity     string   `json:"severity"`
	Source       string   `json:"source"`
	Type         string   `json:"type"`
}

type SyslogConfig struct {
	IsAuditLog  bool   `json:"isAuditLog"`
	RemoteIP    string `json:"remoteIp"`
	RemotePort  string `json:"remotePort"`
	RotateCount int    `json:"rotateCount"`
	Size        int    `json:"size"`
	Syslogd     int    `json:"syslogd"`
	Type        string `json:"type"`
}

type SystemFirmware struct {
	BoardId        int    `json:"boardId"`
	BuildTime      string `json:"buildTime"`
	Manufacturer   string `json:"manufacturer"`
	ManufacturerId int    `json:"manufacturerId"`
	Revision       string `json:"revision"`
	TraceLog       string `json:"traceLog"`
	Type           string `json:"type"`
	Version        string `json:"version"`
}

type Sensor struct {
	Status       string `json:"status"`
	StatusDetail string `json:"statusDetail"`
	Unit         string `json:"unit"`
	Value        string `json:"value"`
	EntityId     string `json:"entityId"`
	SensorId     string `json:"sensorId"`
	ChassisId    string `json:"chassisId"`
	Firmware     string `json:"firmware"`
	Model        string `json:"model"`
	Serial       string `json:"serial"`
	Type         string `json:"type"`
	Vendor       string `json:"vendor"`
}

type Chassis struct {
	ChassisId string `json:"chassisId"`
	Firmware  string `json:"firmware"`
	Model     string `json:"model"`
	Serial    string `json:"serial"`
	Type      string `json:"type"`
	Vendor    string `json:"vendor"`
}

type ChassisStatus struct {
	FPLock                    string `json:"fplock"`
	Intrusion                 string `json:"intrusion"`
	LastPowerEvent            string `json:"lastPowerEvent"`
	PowerEvent                string `json:"powerEvent"`
	PowerRestorePolicy        string `json:"powerRestorePolicy"`
	IsPowerOn                 bool   `json:"isPowerOn"`
	IsDriveFaulty             bool   `json:"isDriveFaulty"`
	IsFanFaulty               bool   `json:"isFanFaulty"`
	IsSleepButtonEnabled      bool   `json:"isSleepButtonEnabled"`
	IsDiagonsticButtonEnabled bool   `json:"isDiagonsticButtonEnabled"`
	IsFPresentButtonEnabled   bool   `json:"isFPresentButtonEnabled"`
	IsPowerButtonEnabled      bool   `json:"isPowerButtonEnabled"`
	IsPowerCtrlFault          bool   `json:"isPowerCtrlFault"`
	IsMainPowerFault          bool   `json:"isMainPowerFault"`
	IsPowerInterLockAct       bool   `json:"isPowerInterLockAct"`
	IsPowerOverLoad           bool   `json:"IsPowerOverLoad"`
}

type Memory struct {
	IsPresent bool   `json:"isPresent"`
	Model     string `json:"model"`
	Size      string `json:"size"`
	Slot      string `json:"slot"`
	Socket    string `json:"socket"`
	Speed     string `json:"speed"`
	Type      string `json:"type"`
}

type SNMPSetting struct {
	TrapComm      string   `json:"trapComm"`
	Node          int      `json:"node"`
	Port          string   `json:"port"`
	ReadOnlyComm  string   `json:"readOnlyComm"`
	ReadWriteComm string   `json:"readWriteComm"`
	TrapIPs       []string `json:"trapIps"`
	TrapVersion   string   `json:"trapVersion"`
}

type SNMPNode struct {
	OID   string `json:"oid"`
	Value string `json:"value"`
}

type CPUSetting struct {
	IsHardwarePatchEnabled     bool   `json:"isHardwarePatchEnabled"`
	IsHyperThreadEnabled       bool   `json:"isHyperThreadEnabled"`
	IsMemoryRankSparingEnabled bool   `json:"isMemoryRankSparingEnabled"`
	IsNUMAEnabled              bool   `json:"isNUMAEnabled"`
	IsTurboModeEnabled         bool   `json:"isTurboModeEnabled"`
	IsVTModelEnabled           bool   `json:"isVTModeEnabled"`
	MemorySize                 int    `json:"memorySize"`
	MemorySpeed                string `json:"memorySpeed"`
	CPUC6State                 string `json:"cpuC6State"`
	LegacyOpROM                string `json:"legacyOpROM"`
}

type Boot struct {
	Mode  string   `json:"mode"`
	Order []string `json:"order"`
}

type BootOption struct {
	Option       string `json:"option"`
	Legacy       bool   `json:"legacy"`
	NextBootOnly bool   `json:"nextBootOnly"`
}

type Switch struct {
	ChassisId   string `json:"chassisId"`
	FailStatus  string `json:"failStatus"`
	FrontLEDs   LED    `json:"frontLEDs"`
	IPAddress   string `json:"ipAddress"`
	PowerStatus string `json:"powerStatus"`
	Slot        string `json:"slot"`
}

type HBAPort struct {
	BladeId int    `json:"bladeId"`
	Name    string `json:"name"`
	Port    int    `json:"port"`
	Slot    int    `json:"slot"`
	WWN     string `json:"wwn"`
	WWPN    string `json:"wwpn"`
}

// network
type PowerProfile struct {
	AveragePowerOverSamplingTime int    `json:"averagePowerOverSamplingTime"`
	CurrentPower                 int    `json:"currentPower"`
	MaxPowerOverSamplingTime     int    `json:"maxPowerOverSamplingTime"`
	MinPowerOverSamplingTime     int    `json:"minPowerOverSamplingTime"`
	Model                        string `json:"model"`
	PowerLimit                   int    `json:"powerLimit"`
	SamplingTime                 int    `json:"samplingTime"`
	TimeStamp                    string `json:"timeStamp"`
}

type ManagementModule struct {
	Condition   string `json:"condition"`
	FailStatus  string `json:"failStatus"`
	FrontLEDs   LED    `json:"frontLEDs"`
	Firmware    string `json:"firmware"`
	IsInstalled bool   `json:"isInstalled"`
	IsActive    bool   `json:"isActive"`
	Parms       string `json:"parms"`
	PowerStatus string `json:"powerStats"`
	Slot        int    `json:"slot"`
}

// network
type RAIDController struct {
	BIOSVersion    string `json:"biosVersion"`
	CPLDVersion    string `json:"cpldVersion"`
	SEEPROMVersion string `json:"seepromVersion"`
	UEFIVersion    string `json:"uefiVersion"`
	Id             string `json:"id"`
	Name           string `json:"name"`
	Serial         string `json:"serial"`
}

// network
type RAIDVirtualDrive struct {
	RAIDControllerId int    `json:"raidControllerId"`
	AccessPolicy     string `json:"accessPolicy"`
	Capacity         int    `json:"capacity"`
	Name             string `json:"name"`
	VirtualDriveId   int    `json:"virtualDriveId"`
	IOPolicy         string `json:"ioPolicy"`
	RAIDType         string `json:"raidType"`
	DiskCachePolicy  string `json:"diskCachePolicy"`
	InitialState     string `json:"initialState"`
	ReadPolicy       string `json:"readPolicy"`
	WritePolicy      string `json:"writePolicy"`
	SpanDepth        int    `json:"spanDepth"`
	StripeSize       string `json:"stripeSize"`
}

type RAIDDrive struct {
	Capacity           int    `json:"capacity"`
	ConfigurationState string `json:"configurationState"`
	RAIDController     string `json:"raidController"`
	RAIDControllerID   int    `json:"raidControllerId"`
	DeviceID           int    `json:"deviceId"`
	IsPresent          bool   `json:"isPresent"`
	Model              string `json:"model"`
	Serial             string `json:"serial"`
	Slot               int    `json:"slot"`
	Speed              string `json:"speed"`
	Type               string `json:"type"`
}

// SystemDrive describes one storage device (disk, SSD, etc.) on the host.
type SystemDrive struct {

	// The size of the disk in Bytes
	Id int `json:"id"`

	// The size of the disk in Bytes
	Capacity int `json:"capacity"`

	// Hardware model
	Model string `json:"model,omitempty"`

	// The serial number of the device
	Serial string `json:"serial"`

	// The serial number of the device
	Protocol string `json:"protocol"`

	// The serial number of the device
	State string `json:"state"`

	Status string `json:"status"`

	Type string `json:"type"`
}

// NIC describes one network interface on the host.
type NIC struct {
	// The name of the NIC, e.g. "nic-1"
	Name string `json:"name"`

	// The name of the model, e.g. "virt-io"
	Model string `json:"model"`

	// The device MAC addr
	// +kubebuilder:validation:Pattern=`[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}`
	MAC string `json:"mac"`

	// The IP address of the device
	IP string `json:"ip"`

	// The speed of the device
	SpeedGbps int `json:"speedGbps"`

	// The status of the device
	Status string `json:"status"`

	//type of the network interface
	Type string `json:"type"`
}

// network
type Network struct {
	HostName          string `json:"hostname"`
	NetworkInterfaces []NIC  `json:"networkInterfaces"`
}

// Firmware describes the firmware on the host.
type Firmware struct {
	// The BIOS for this firmware
	BIOS BIOS `json:"bios"`
}

// BIOS describes the BIOS version on the host.
type BIOS struct {
	// The release/build date for this BIOS
	Date string `json:"date"`

	// The vendor name for this BIOS
	Vendor string `json:"vendor"`

	// The version of the BIOS
	Version string `json:"version"`
}

type Power struct {
	PowerState string `json:"powerState"`
}

// HardwareDetails collects all of the information about hardware
// discovered on the host.
type HardwareDetails struct {
	//ServerInfo       ServerInfo       `json:"server"`
	CPU []CPU `json:"CPUs,omitempty"`
	//GPU              []GPU            `json:"GPUs,omitempty"`
	NIC Network `json:"NIC,omitempty"`
	//FRU              []FRU            `json:"FRUs,omitempty"`
	//Sensor           []Sensor         `json:"sensors,omitempty"`
	//Memory           Memory           `json:"memory,omitempty"`
	//SNMPSetting      SNMPSetting      `json:"SNMPSetting,omitempty"`
	//SNMPNode         SNMPNode         `json:"SNMPNode,omitempty"`
	//CPUSetting       CPUSetting       `json:"CPUSetting,omitempty"`
	//Chassis          Chassis          `json:"chassis,omitempty"`
	//ChassisStatus    ChassisStatus    `json:"chassisStatus,omitempty"`
	//Boot             Boot             `json:"boot,omitempty"`
	//HBAPort          HBAPort          `json:"HBAPort,omitempty"`
	//PowerProfile     PowerProfile     `json:"powerProfile,omitempty"`
	//ManagementModuel ManagementModule `json:"managementModule,omitempty"`
	//RAIDController   RAIDController   `json:"RAIDController,omitempty"`
	//RAIDDrive        RAIDDrive        `json:"RAIDDrive,omitempty"`
	BMC BMCDetails `json:"BMC,omitempty"`
}

// CredentialsStatus contains the reference and version of the last
// set of BMC credentials the controller was able to validate.
type CredentialsStatus struct {
	Reference *corev1.SecretReference `json:"credentials,omitempty"`
	Version   string                  `json:"credentialsVersion,omitempty"`
}

// Match compares the saved status information with the name and
// content of a secret object.
func (cs CredentialsStatus) Match(secret corev1.Secret) bool {
	switch {
	case cs.Reference == nil:
		return false
	case cs.Reference.Name != secret.ObjectMeta.Name:
		return false
	case cs.Reference.Namespace != secret.ObjectMeta.Namespace:
		return false
	case cs.Version != secret.ObjectMeta.ResourceVersion:
		return false
	}
	return true
}

// OperationMetric contains metadata about an operation (inspection,
// provisioning, etc.) used for tracking metrics.
type OperationMetric struct {
	// +nullable
	Start metav1.Time `json:"start,omitempty"`
	// +nullable
	End metav1.Time `json:"end,omitempty"`
}

// Duration returns the length of time that was spent on the
// operation. If the operation is not finished, it returns 0.
func (om OperationMetric) Duration() time.Duration {
	if om.Start.IsZero() {
		return 0
	}
	return om.End.Time.Sub(om.Start.Time)
}

// OperationHistory holds information about operations performed on a
// host.
type OperationHistory struct {
	Register    OperationMetric `json:"register,omitempty"`
	Inspect     OperationMetric `json:"inspect,omitempty"`
	Provision   OperationMetric `json:"provision,omitempty"`
	Deprovision OperationMetric `json:"deprovision,omitempty"`
}

// ServerStatus defines the observed state of Server
type ServerStatus struct {
	// Important: Run "operator-sdk generate k8s" to regenerate code
	// after modifying this file

	// OperationalStatus holds the status of the host
	// +kubebuilder:validation:Enum="";OK;discovered;error
	OperationalStatus OperationalStatus `json:"operationalStatus"`

	// ErrorType indicates the type of failure encountered when the
	// OperationalStatus is OperationalStatusError
	// +kubebuilder:validation:Enum=registration error;inspection error;provisioning error;power management error
	ErrorType ErrorType `json:"errorType,omitempty"`

	// LastUpdated identifies when this status was last observed.
	// +optional
	LastUpdated *metav1.Time `json:"lastUpdated,omitempty"`

	// The name of the profile matching the hardware details.
	HardwareProfile string `json:"hardwareProfile"`

	// The hardware discovered to exist on the host.
	HardwareDetails *HardwareDetails `json:"hardware,omitempty"`

	// Information tracked by the provisioner.
	Provisioning ProvisionStatus `json:"provisioning"`

	// the last credentials we were able to validate as working
	GoodCredentials CredentialsStatus `json:"goodCredentials,omitempty"`

	// the last credentials we sent to the provisioning backend
	TriedCredentials CredentialsStatus `json:"triedCredentials,omitempty"`

	// the last error message reported by the provisioning subsystem
	ErrorMessage string `json:"errorMessage"`

	// indicator for whether or not the host is powered on
	PoweredOn bool `json:"poweredOn"`

	// OperationHistory holds information about operations performed
	// on this host.
	OperationHistory OperationHistory `json:"operationHistory"`
}

// ProvisionStatus holds the state information for a single target.
type ProvisionStatus struct {
	// An indiciator for what the provisioner is doing with the host.
	State ProvisioningState `json:"state"`

	// The machine's UUID from the underlying provisioning tool
	ID string `json:"ID"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Server is the Schema for the servers API
// +k8s:openapi-gen=true
// +kubebuilder:resource:shortName=bmh;bmhost
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.operationalStatus",description="Operational status"
// +kubebuilder:printcolumn:name="BMC",type="string",JSONPath=".spec.bmc.address",description="Address of management controller"
// +kubebuilder:printcolumn:name="Puma",type="string",JSONPath=".spec.puma.address",description="Address of puma management controller"
// +kubebuilder:printcolumn:name="Hardware Profile",type="string",JSONPath=".status.hardwareProfile",description="The type of hardware detected"
// +kubebuilder:printcolumn:name="Online",type="string",JSONPath=".spec.online",description="Whether the host is online or not"
// +kubebuilder:printcolumn:name="Error",type="string",JSONPath=".status.errorMessage",description="Most recent error"
type Server struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ServerSpec   `json:"spec,omitempty"`
	Status ServerStatus `json:"status,omitempty"`
}

// Available returns true if the host is available to be provisioned.
func (host *Server) Available() bool {
	if host.Spec.ConsumerRef != nil {
		return false
	}
	if host.GetDeletionTimestamp() != nil {
		return false
	}
	if host.HasError() {
		return false
	}
	return true
}

// SetErrorMessage updates the ErrorMessage in the host Status struct
// when necessary and returns true when a change is made or false when
// no change is made.
func (host *Server) SetErrorMessage(errType ErrorType, message string) (dirty bool) {
	if host.Status.OperationalStatus != OperationalStatusError {
		host.Status.OperationalStatus = OperationalStatusError
		dirty = true
	}
	if host.Status.ErrorType != errType {
		host.Status.ErrorType = errType
		dirty = true
	}
	if host.Status.ErrorMessage != message {
		host.Status.ErrorMessage = message
		dirty = true
	}
	return dirty
}

// ClearError removes any existing error message.
func (host *Server) ClearError() (dirty bool) {
	dirty = host.SetOperationalStatus(OperationalStatusOK)
	var emptyErrType ErrorType = ""
	if host.Status.ErrorType != emptyErrType {
		host.Status.ErrorType = emptyErrType
		dirty = true
	}
	if host.Status.ErrorMessage != "" {
		host.Status.ErrorMessage = ""
		dirty = true
	}
	return dirty
}

// setLabel updates the given label when necessary and returns true
// when a change is made or false when no change is made.
func (host *Server) setLabel(name, value string) bool {
	if host.Labels == nil {
		host.Labels = make(map[string]string)
	}
	if host.Labels[name] != value {
		host.Labels[name] = value
		return true
	}
	return false
}

// getLabel returns the value associated with the given label. If
// there is no value, an empty string is returned.
func (host *Server) getLabel(name string) string {
	if host.Labels == nil {
		return ""
	}
	return host.Labels[name]
}

// NeedsHardwareProfile returns true if the profile is not set
func (host *Server) NeedsHardwareProfile() bool {
	return host.Status.HardwareProfile == ""
}

// HardwareProfile returns the hardware profile name for the host.
func (host *Server) HardwareProfile() string {
	return host.Status.HardwareProfile
}

// SetHardwareProfile updates the hardware profile name and returns
// true when a change is made or false when no change is made.
func (host *Server) SetHardwareProfile(name string) (dirty bool) {
	if host.Status.HardwareProfile != name {
		host.Status.HardwareProfile = name
		dirty = true
	}
	return dirty
}

// SetOperationalStatus updates the OperationalStatus field and returns
// true when a change is made or false when no change is made.
func (host *Server) SetOperationalStatus(status OperationalStatus) bool {
	if host.Status.OperationalStatus != status {
		host.Status.OperationalStatus = status
		return true
	}
	return false
}

// OperationalStatus returns the contents of the OperationalStatus
// field.
func (host *Server) OperationalStatus() OperationalStatus {
	return host.Status.OperationalStatus
}

// HasError returns a boolean indicating whether there is an error
// set for the host.
func (host *Server) HasError() bool {
	return host.Status.ErrorMessage != ""
}

// CredentialsKey returns a NamespacedName suitable for loading the
// Secret containing the credentials associated with the host.
func (host *Server) PumaCredentialsKey() types.NamespacedName {
	return types.NamespacedName{
		Name:      host.Spec.Puma.CredentialsName,
		Namespace: host.ObjectMeta.Namespace,
	}
}

// CredentialsKey returns a NamespacedName suitable for loading the
// Secret containing the credentials associated with the host.
func (host *Server) BMCCredentialsKey() types.NamespacedName {
	return types.NamespacedName{
		Name:      host.Spec.BMC.CredentialsName,
		Namespace: host.ObjectMeta.Namespace,
	}
}

// NeedsHardwareInspection looks at the state of the host to determine
// if hardware inspection should be run.
func (host *Server) NeedsHardwareInspection() bool {
	if host.WasProvisioned() {
		// Never perform inspection if we have already provisioned
		// this host, because we don't want to reboot it.
		return false
	}
	return host.Status.HardwareDetails == nil
}

// NeedsProvisioning compares the settings with the provisioning
// status and returns true when more work is needed or false
// otherwise.
func (host *Server) NeedsProvisioning() bool {
	if !host.Spec.Online {
		// The host is not supposed to be powered on.
		return false
	}
	return false
}

// WasProvisioned returns true when we think we have placed an image
// on the host.
func (host *Server) WasProvisioned() bool {
	return false
}

// NeedsDeprovisioning compares the settings with the provisioning
// status and returns true when the host should be deprovisioned.
func (host *Server) NeedsDeprovisioning() bool {
	return false
}

// UpdateGoodCredentials modifies the GoodCredentials portion of the
// Status struct to record the details of the secret containing
// credentials known to work.
func (host *Server) UpdateGoodCredentials(currentSecret corev1.Secret) {
	host.Status.GoodCredentials.Version = currentSecret.ObjectMeta.ResourceVersion
	host.Status.GoodCredentials.Reference = &corev1.SecretReference{
		Name:      currentSecret.ObjectMeta.Name,
		Namespace: currentSecret.ObjectMeta.Namespace,
	}
}

// UpdateTriedCredentials modifies the TriedCredentials portion of the
// Status struct to record the details of the secret containing
// credentials known to work.
func (host *Server) UpdateTriedCredentials(currentSecret corev1.Secret) {
	host.Status.TriedCredentials.Version = currentSecret.ObjectMeta.ResourceVersion
	host.Status.TriedCredentials.Reference = &corev1.SecretReference{
		Name:      currentSecret.ObjectMeta.Name,
		Namespace: currentSecret.ObjectMeta.Namespace,
	}
}

// NewEvent creates a new event associated with the object and ready
// to be published to the kubernetes API.
func (host *Server) NewEvent(reason, message string) corev1.Event {
	t := metav1.Now()
	return corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: reason + "-",
			Namespace:    host.ObjectMeta.Namespace,
		},
		InvolvedObject: corev1.ObjectReference{
			Kind:       "Server",
			Namespace:  host.Namespace,
			Name:       host.Name,
			UID:        host.UID,
			APIVersion: SchemeGroupVersion.String(),
		},
		Reason:  reason,
		Message: message,
		Source: corev1.EventSource{
			Component: "app-server-controller",
		},
		FirstTimestamp:      t,
		LastTimestamp:       t,
		Count:               1,
		Type:                corev1.EventTypeNormal,
		ReportingController: "example.inc/server-controller",
		Related:             host.Spec.ConsumerRef,
	}
}

// OperationMetricForState returns a pointer to the metric for the given
// provisioning state.
func (host *Server) OperationMetricForState(operation ProvisioningState) (metric *OperationMetric) {
	history := &host.Status.OperationHistory
	switch operation {
	case StateRegistering:
		metric = &history.Register
	case StateInspecting:
		metric = &history.Inspect
	}
	return
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ServerList contains a list of Server
type ServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Server `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Server{}, &ServerList{})
}
