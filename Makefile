namespace:
	kubectl create namespace puma
recreate:
	#operator-sdk generate k8s
	operator-sdk generate crds
create:
	# Setup Service Account
	kubectl create -f deploy/service_account.yaml 
	# Setup RBAC
	kubectl create -f deploy/role.yaml 
	kubectl create -f deploy/role_binding.yaml
	# Setup the CRD
	kubectl create -f deploy/crds/app.example.com_servers_crd.yaml
	# Deploy the app-operator
	kubectl create -f deploy/operator.yaml
	# Create an AppService CR
	# The default controller will watch for AppService objects and create a pod for each CR
	kubectl create -f deploy/crds/app.example.com_v1alpha1_server_cr.yaml

cleanup:
	# Cleanup
	kubectl delete -f deploy/crds/app.example.com_v1alpha1_server_cr.yaml
	kubectl delete -f deploy/operator.yaml
	kubectl delete -f deploy/role.yaml
	kubectl delete -f deploy/role_binding.yaml
	kubectl delete -f deploy/service_account.yaml
	kubectl delete -f deploy/crds/app.example.com_servers_crd.yaml
monitor:	
	operator-sdk run --local --operator-flags="--zap-level=debug --zap-encoder=console"
local:
	operator-sdk up local --namespace=puma 
test:
	operator-sdk run --local --operator-flags "--test-mode"
deletenowait:
	kubectl delete -f deploy/crds/app.example.com_servers_crd.yaml --wait=false
secrets:
	kubectl create secret generic example-bmc-secret --from-literal=username=admin --from-literal=password='cmb9.admin'
	kubectl create secret generic example-puma-secret --from-literal=username=admin --from-literal=password='Hitachi1'
