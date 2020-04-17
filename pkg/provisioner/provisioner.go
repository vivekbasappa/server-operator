package provisioner

import (
	"time"

	appv1alpha1 "github.com/example-inc/server-operator/pkg/apis/app/v1alpha1"
	"github.com/example-inc/server-operator/pkg/bmc"
	"github.com/example-inc/server-operator/pkg/pumas"
)

/*
Package provisioning defines the API for talking to the provisioning backend.
*/

// EventPublisher is a function type for publishing events associated
// with provisioning.
type EventPublisher func(reason, message string)

// Factory is the interface for creating new Provisioner objects.
type Factory func(host *appv1alpha1.Server, pumaCreds pumas.Credentials, bmcCreds bmc.Credentials, publish EventPublisher) (Provisioner, error)

// HostConfigData retrieves host configuration data
type HostConfigData interface {
	// UserData is the interface for a function to retrieve user
	// data for a host being provisioned.
	UserData() (string, error)

	// NetworkData is the interface for a function to retrieve netwok
	// configuration for a host.
	NetworkData() (string, error)

	// TODO add MetaDataSource method
}

// Provisioner holds the state information for talking to the
// provisioning backend.
type Provisioner interface {
	// ValidateManagementAccess tests the connection information for
	// the host to verify that the location and credentials work. The
	// boolean argument tells the provisioner whether the current set
	// of credentials it has are different from the credentials it has
	// previously been using, without implying that either set of
	// credentials is correct.
	ValidateManagementAccess(credentialsChanged bool) (result Result, err error)

	// InspectHardware updates the HardwareDetails field of the host with
	// details of devices discovered on the hardware. It may be called
	// multiple times, and should return true for its dirty flag until the
	// inspection is completed.
	InspectHardware() (result Result, details *appv1alpha1.HardwareDetails, err error)

	// UpdateHardwareState fetches the latest hardware state of the
	// server and updates the HardwareDetails field of the host with
	// details. It is expected to do this in the least expensive way
	// possible, such as reading from a cache, and return dirty only
	// if any state information has changed.
	UpdateHardwareState() (result Result, err error)

	// Adopt brings an externally-provisioned host under management by
	// the provisioner.
	//Adopt() (result Result, err error)

	// Delete removes the host from the provisioning system. It may be
	// called multiple times, and should return true for its dirty
	// flag until the deprovisioning operation is completed.
	//Delete() (result Result, err error)

	// PowerOn ensures the server is powered on
	PowerOn() (result Result, err error)

	// PowerOff ensures the server is powered off
	PowerOff() (result Result, err error)
}

// Result holds the response from a call in the Provsioner API.
type Result struct {
	// Dirty indicates whether the host object needs to be saved.
	Dirty bool
	// RequeueAfter indicates how long to wait before making the same
	// Provisioner call again. The request should only be requeued if
	// Dirty is also true.
	RequeueAfter time.Duration
	// Any error message produced by the provisioner.
	ErrorMessage string
}
