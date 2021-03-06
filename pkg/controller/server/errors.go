package server

import (
	"fmt"
)

// EmptyBMCAddressError is returned when the BMC address field
// for a host is empty
type EmptyBMCAddressError struct {
	message string
}

func (e EmptyBMCAddressError) Error() string {
	return fmt.Sprintf("Empty BMC address %s",
		e.message)
}

// EmptyBMCSecretError is returned when the BMC secret
// for a host is empty
type EmptyBMCSecretError struct {
	message string
}

func (e EmptyBMCSecretError) Error() string {
	return fmt.Sprintf("No BMC CredentialsName defined %s",
		e.message)
}

// ResolveBMCSecretRefError is returned when the BMC secret
// for a host is defined but cannot be found
type ResolveBMCSecretRefError struct {
	message string
}

func (e ResolveBMCSecretRefError) Error() string {
	return fmt.Sprintf("BMC CredentialsName secret doesn't exist %s",
		e.message)
}

// SaveBMCSecretOwnerError is returned when we
// fail to set the owner of a secret
type SaveBMCSecretOwnerError struct {
	message string
}

func (e SaveBMCSecretOwnerError) Error() string {
	return fmt.Sprintf("Failed to set owner of BMC secret %s",
		e.message)
}

// EmptyPumaAddressError is returned when the Puma address field
// for a host is empty
type EmptyPumaAddressError struct {
	message string
}

func (e EmptyPumaAddressError) Error() string {
	return fmt.Sprintf("Empty Puma address %s",
		e.message)
}

// EmptyPumaSecretError is returned when the BMC secret
// for a host is empty
type EmptyPumaSecretError struct {
	message string
}

func (e EmptyPumaSecretError) Error() string {
	return fmt.Sprintf("No Puma CredentialsName defined %s",
		e.message)
}

// ResolvePumaSecretRefError is returned when the BMC secret
// for a host is defined but cannot be found
type ResolvePumaSecretRefError struct {
	message string
}

func (e ResolvePumaSecretRefError) Error() string {
	return fmt.Sprintf("Puma CredentialsName secret doesn't exist %s",
		e.message)
}

// SavePumaSecretOwnerError is returned when we
// fail to set the owner of a secret
type SavePumaSecretOwnerError struct {
	message string
}

func (e SavePumaSecretOwnerError) Error() string {
	return fmt.Sprintf("Failed to set owner of Puma secret %s",
		e.message)
}

// NoDataInSecretError is returned when host configuration
// data were not found in referenced secret
type NoDataInSecretError struct {
	secret string
	key    string
}

func (e NoDataInSecretError) Error() string {
	return fmt.Sprintf("Secret %s does not contain key %s", e.secret, e.key)
}
