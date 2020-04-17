package server

import (
	"context"
	"fmt"

	"github.com/pkg/errors"

	appv1alpha1 "github.com/example-inc/server-operator/pkg/apis/app/v1alpha1"

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// hostConfigData is an implementation of host configuration data interface.
// Object is able to retrive data from secrets referenced in a host spec
type hostConfigData struct {
	host   *appv1alpha1.Server
	log    logr.Logger
	client client.Client
}

// Generic method for data extraction from a Secret. Function uses dataKey
// parameter to detirmine which data to return in case secret contins multiple
// keys
func (hcd *hostConfigData) getSecretData(name, namespace, dataKey string) (string, error) {
	secret := &corev1.Secret{}
	key := types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}
	if err := hcd.client.Get(context.TODO(), key, secret); err != nil {
		errMsg := fmt.Sprintf("failed to fetch user data from secret %s defined in namespace %s", name, namespace)
		return "", errors.Wrap(err, errMsg)
	}

	data, ok := secret.Data[dataKey]
	if ok {
		return string(data), nil
	}
	// There is no data under dataKey (userData or networkData).
	// Tring to falback to 'value' key
	if data, ok = secret.Data["value"]; !ok {
		hostConfigDataError.WithLabelValues(dataKey).Inc()
		return "", NoDataInSecretError{secret: name, key: dataKey}
	}

	return string(data), nil
}
