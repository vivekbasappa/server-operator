package server

import (
	"fmt"

	appv1alpha1 "github.com/example-inc/server-operator/pkg/apis/app/v1alpha1"
	"github.com/example-inc/server-operator/pkg/provisioner"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// hostStateMachine is a finite state machine that manages transitions between
// the states of a Server.
type hostStateMachine struct {
	Host        *appv1alpha1.Server
	NextState   appv1alpha1.ProvisioningState
	Reconciler  *ReconcileServer
	Provisioner provisioner.Provisioner
}

func newHostStateMachine(host *appv1alpha1.Server,
	reconciler *ReconcileServer,
	provisioner provisioner.Provisioner) *hostStateMachine {
	currentState := host.Status.Provisioning.State
	r := hostStateMachine{
		Host:        host,
		NextState:   currentState, // Remain in current state by default
		Reconciler:  reconciler,
		Provisioner: provisioner,
	}
	return &r
}

type stateHandler func(*reconcileInfo) actionResult

func (hsm *hostStateMachine) handlers() map[appv1alpha1.ProvisioningState]stateHandler {
	return map[appv1alpha1.ProvisioningState]stateHandler{
		appv1alpha1.StateNone:                 hsm.handleNone,
		appv1alpha1.StateRegistering:          hsm.handleRegistering,
		appv1alpha1.StateRegistrationError:    hsm.handleRegistrationError,
		appv1alpha1.StateInspecting:           hsm.handleInspecting,
		appv1alpha1.StateMatchProfile:         hsm.handleMatchProfile,
		appv1alpha1.StateReady:                hsm.handleReady,
		appv1alpha1.StatePowerManagementError: hsm.handlePowerManagementError,
	}
}

func recordStateBegin(host *appv1alpha1.Server, state appv1alpha1.ProvisioningState, time metav1.Time) {
	if nextMetric := host.OperationMetricForState(state); nextMetric != nil {
		if nextMetric.Start.IsZero() || !nextMetric.End.IsZero() {
			*nextMetric = appv1alpha1.OperationMetric{
				Start: time,
			}
		}
	}
}

func recordStateEnd(info *reconcileInfo, host *appv1alpha1.Server, state appv1alpha1.ProvisioningState, time metav1.Time) {
	if prevMetric := host.OperationMetricForState(state); prevMetric != nil {
		if !prevMetric.Start.IsZero() {
			prevMetric.End = time
			info.postSaveCallbacks = append(info.postSaveCallbacks, func() {
				observer := stateTime[state].With(hostMetricLabels(info.request))
				observer.Observe(prevMetric.Duration().Seconds())
			})
		}
	}
}

func (hsm *hostStateMachine) updateHostStateFrom(initialState appv1alpha1.ProvisioningState,
	info *reconcileInfo) {
	if hsm.NextState != initialState {
		info.log.Info("changing provisioning state",
			"old", initialState,
			"new", hsm.NextState)
		now := metav1.Now()
		recordStateEnd(info, hsm.Host, initialState, now)
		recordStateBegin(hsm.Host, hsm.NextState, now)
		info.postSaveCallbacks = append(info.postSaveCallbacks, func() {
			stateChanges.With(stateChangeMetricLabels(initialState, hsm.NextState)).Inc()
		})
		hsm.Host.Status.Provisioning.State = hsm.NextState
	}
}

func (hsm *hostStateMachine) ReconcileState(info *reconcileInfo) actionResult {
	initialState := hsm.Host.Status.Provisioning.State
	defer hsm.updateHostStateFrom(initialState, info)

	if hsm.checkInitiateDelete() {
		info.log.Info("Initiating host deletion")
		return actionComplete{}
	}
	// TODO: In future we should always re-register the host if required,
	// rather than initiate a transistion back to the Registering state.
	if hsm.shouldInitiateRegister(info) {
		info.log.Info("Initiating host registration")
		hostRegistrationRequired.Inc()
		return actionComplete{}
	}

	if stateHandler, found := hsm.handlers()[initialState]; found {
		return stateHandler(info)
	}

	info.log.Info("No handler found for state", "state", initialState)
	return actionError{fmt.Errorf("No handler found for state \"%s\"", initialState)}
}

func (hsm *hostStateMachine) checkInitiateDelete() bool {
	if hsm.Host.DeletionTimestamp.IsZero() {
		// Delete not requested
		return false
	}

	return true
}

func (hsm *hostStateMachine) shouldInitiateRegister(info *reconcileInfo) bool {
	changeState := false
	if hsm.Host.DeletionTimestamp.IsZero() {
		switch hsm.NextState {
		default:
			changeState = !hsm.Host.Status.GoodCredentials.Match(*info.bmcCredsSecret)
		case appv1alpha1.StateNone:
		case appv1alpha1.StateRegistering, appv1alpha1.StateRegistrationError:
		}
	}
	if changeState {
		hsm.NextState = appv1alpha1.StateRegistering
	}
	return changeState
}

func (hsm *hostStateMachine) handleNone(info *reconcileInfo) actionResult {
	// Running the state machine at all means we have successfully validated
	// the BMC credentials once, so we can move to the Registering state.
	hsm.Host.ClearError()
	hsm.NextState = appv1alpha1.StateRegistering
	return actionComplete{}
}

func (hsm *hostStateMachine) handleRegistering(info *reconcileInfo) actionResult {
	actResult := hsm.Reconciler.actionRegistering(hsm.Provisioner, info)

	switch actResult.(type) {
	case actionComplete:
		// TODO: In future this state should only occur before the host is
		// registered the first time (though we must always check and
		// re-register the host regardless of the current state). That will
		// eliminate the need to determine which state we came from here.
		switch {
		case hsm.Host.NeedsHardwareInspection():
			hsm.NextState = appv1alpha1.StateInspecting
		case hsm.Host.NeedsHardwareProfile():
			hsm.NextState = appv1alpha1.StateMatchProfile
		default:
			hsm.NextState = appv1alpha1.StateReady
		}
	case actionFailed:
		hsm.NextState = appv1alpha1.StateRegistrationError
	}
	return actResult
}

func (hsm *hostStateMachine) handleRegistrationError(info *reconcileInfo) actionResult {
	if !hsm.Host.Status.TriedCredentials.Match(*info.bmcCredsSecret) {
		info.log.Info("Modified credentials detected; will retry registration")
		hsm.NextState = appv1alpha1.StateRegistering
		return actionComplete{}
	}
	return actionFailed{}
}

func (hsm *hostStateMachine) handleInspecting(info *reconcileInfo) actionResult {
	actResult := hsm.Reconciler.actionInspecting(hsm.Provisioner, info)
	if _, complete := actResult.(actionComplete); complete {
		hsm.NextState = appv1alpha1.StateMatchProfile
	}
	return actResult
}

func (hsm *hostStateMachine) handleMatchProfile(info *reconcileInfo) actionResult {
	actResult := hsm.Reconciler.actionMatchProfile(hsm.Provisioner, info)
	if _, complete := actResult.(actionComplete); complete {
		hsm.NextState = appv1alpha1.StateReady
	}
	return actResult
}

func (hsm *hostStateMachine) handleReady(info *reconcileInfo) actionResult {
	actResult := hsm.Reconciler.actionManageReady(hsm.Provisioner, info)

	switch r := actResult.(type) {
	case actionComplete:
	case actionFailed:
		switch r.ErrorType {
		case appv1alpha1.PowerManagementError:
			hsm.NextState = appv1alpha1.StatePowerManagementError
		case appv1alpha1.RegistrationError:
			hsm.NextState = appv1alpha1.StateRegistrationError
		}
	}
	return actResult
}

func (hsm *hostStateMachine) handlePowerManagementError(info *reconcileInfo) actionResult {
	switch {
	case hsm.Host.WasProvisioned():
	default:
		hsm.NextState = appv1alpha1.StateReady
	}
	return actionComplete{}
}
