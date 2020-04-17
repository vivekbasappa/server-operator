package bmc

import (
	"fmt"
)

// CredentialsValidationError is returned when the provided BMC credentials
// are invalid (e.g. null)
type CredentialsValidationError struct {
	message string
}

func (e CredentialsValidationError) Error() string {
	return fmt.Sprintf("Validation error with BMC credentials: %s",
		e.message)
}
