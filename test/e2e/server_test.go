// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package e2e

import (
	goctx "context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	apis "github.com/example-inc/server-operator/pkg/apis"
	appv1alpha1 "github.com/example-inc/server-operator/pkg/apis/app/v1alpha1"

	framework "github.com/operator-framework/operator-sdk/pkg/test"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
)

var (
	retryInterval        = time.Second * 5
	timeout              = time.Second * 10
	cleanupRetryInterval = time.Second * 1
	cleanupTimeout       = time.Second * 5
)

// Set up the test system to know about our types and return a
// context.
func setup(t *testing.T) *framework.TestCtx {
	bmhList := &appv1alpha1.ServerList{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Server",
			APIVersion: "servers.app.io/v1alpha1",
		},
	}
	err := framework.AddToFrameworkScheme(apis.AddToScheme, bmhList)
	if err != nil {
		t.Fatalf("failed to add custom resource scheme to framework: %v", err)
	}

	t.Parallel()
	ctx := framework.NewTestCtx(t)

	err = ctx.InitializeClusterResources(&framework.CleanupOptions{TestContext: ctx, Timeout: cleanupTimeout, RetryInterval: cleanupRetryInterval})
	if err != nil {
		t.Fatalf("failed to initialize cluster resources: %v", err)
	}
	t.Log("Initialized cluster resources")

	makeSecret(t, ctx, "bmc-creds-valid", "User", "Pass")
	makeSecret(t, ctx, "bmc-creds-no-user", "", "Pass")
	makeSecret(t, ctx, "bmc-creds-no-pass", "User", "")

	makeSecret(t, ctx, "puma-creds-valid", "User", "Pass")
	makeSecret(t, ctx, "puma-creds-no-user", "", "Pass")
	makeSecret(t, ctx, "puma-creds-no-pass", "User", "")

	return ctx
}

// Create a new Server instance.
func newHost(t *testing.T, ctx *framework.TestCtx, name string, spec *appv1alpha1.ServerSpec) *appv1alpha1.Server {
	namespace, err := ctx.GetNamespace()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Using namespace: %v\n", namespace)

	host := &appv1alpha1.Server{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Server",
			APIVersion: "servers.appv1alpha1.org/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", ctx.GetID(), name),
			Namespace: namespace,
		},
		Spec: *spec,
	}

	return host
}

// Create a Server and publish it to the test system.
func makeHost(t *testing.T, ctx *framework.TestCtx, name string, spec *appv1alpha1.ServerSpec) *appv1alpha1.Server {
	host := newHost(t, ctx, name, spec)

	// get global framework variables
	f := framework.Global

	// use TestCtx's create helper to create the object and add a
	// cleanup function for the new object
	err := f.Client.Create(
		goctx.TODO(),
		host,
		&framework.CleanupOptions{
			TestContext:   ctx,
			Timeout:       cleanupTimeout,
			RetryInterval: cleanupRetryInterval})
	if err != nil {
		t.Fatal(err)
	}

	return host
}

func makeSecret(t *testing.T, ctx *framework.TestCtx, name string, username string, password string) {

	namespace, err := ctx.GetNamespace()
	if err != nil {
		t.Fatal(err)
	}

	data := make(map[string][]byte)
	data["username"] = []byte(base64.StdEncoding.EncodeToString([]byte(username)))
	data["password"] = []byte(base64.StdEncoding.EncodeToString([]byte(password)))

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: data,
	}

	f := framework.Global
	err = f.Client.Create(
		goctx.TODO(),
		secret,
		&framework.CleanupOptions{
			TestContext:   ctx,
			Timeout:       cleanupTimeout,
			RetryInterval: cleanupRetryInterval})
	if err != nil {
		t.Fatal(err)
	}

}

type DoneFunc func(host *appv1alpha1.Server) (bool, error)

func refreshHost(host *appv1alpha1.Server) error {
	f := framework.Global
	namespacedName := types.NamespacedName{
		Namespace: host.ObjectMeta.Namespace,
		Name:      host.ObjectMeta.Name,
	}
	return f.Client.Get(goctx.TODO(), namespacedName, host)
}

func waitForHostStateChange(t *testing.T, host *appv1alpha1.Server, isDone DoneFunc) *appv1alpha1.Server {
	instance := &appv1alpha1.Server{}
	instance.ObjectMeta = host.ObjectMeta

	err := wait.Poll(retryInterval, timeout, func() (done bool, err error) {
		t.Log("polling host for updates")
		refreshHost(instance)
		if err != nil {
			return false, err
		}
		done, err = isDone(instance)
		return done, err
	})
	if err != nil {
		t.Fatal(err)
	}

	return instance
}

func TestManageHardwareDetails(t *testing.T) {
	ctx := setup(t)
	defer ctx.Cleanup()

	f := framework.Global

	host := makeHost(t, ctx, "hardware-profile",
		&appv1alpha1.ServerSpec{
			BMC: appv1alpha1.BMCDetails{
				Address:                        "192.168.122.1",
				CredentialsName:                "bmc-creds-valid",
				DisableCertificateVerification: true,
			},
			Puma: appv1alpha1.PumaDetails{
				Address:                        "https://192.168.122.2:8444/v8/compute",
				CredentialsName:                "puma-creds-valid",
				DisableCertificateVerification: true,
			},
		})

	// Details should be filled in when the host is created...
	waitForHostStateChange(t, host, func(host *appv1alpha1.Server) (done bool, err error) {
		t.Logf("details: %v", host.Status.HardwareDetails)
		if host.Status.HardwareDetails != nil {
			return true, nil
		}
		return false, nil
	})

	if err := f.Client.Delete(goctx.TODO(), host); err != nil {
		t.Fatal(err)
	}

	// and removed when the host is deleted.
	waitForHostStateChange(t, host, func(host *appv1alpha1.Server) (done bool, err error) {
		t.Logf("details: %v", host.Status.HardwareDetails)
		if host.Status.HardwareDetails == nil {
			return true, nil
		}
		return false, nil
	})
}
