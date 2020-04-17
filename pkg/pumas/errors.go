package pumas

import (
	"fmt"
)

// CredentialsValidationError is returned when the provided BMC credentials
// are invalid (e.g. null)
type CredentialsValidationError struct {
	message string
}

func (e CredentialsValidationError) Error() string {
	return fmt.Sprintf("Validation error with Puma credentials: %s",
		e.message)
}
