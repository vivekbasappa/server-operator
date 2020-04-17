package controller

import (
	"github.com/example-inc/server-operator/pkg/controller/server"
)

func init() {
	// AddToManagerFuncs is a list of functions to create controllers and add them to a manager.
	AddToManagerFuncs = append(AddToManagerFuncs, server.Add)
}
