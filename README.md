# Kerberos Sidecar Injector

This repo was initiated as a copy of our [filer-sidecar-injector](https://github.com/StatCan/filer-sidecar-injector) repo as they both share a very similar design. 
This is used to create a Kubernetes [MutatingAdmissionWebhook](https://kubernetes.io/docs/admin/admission-controllers/#mutatingadmissionwebhook-beta-in-19) that injects a sidecar container into a pod prior to the persistence of the object. This sidecar is an alpine image based on the [kerberos sidecar image](https://gitlab.k8s.cloud.statcan.ca/cloudnative/docker/kerberos-sidecar) initially designed by our Cloud Native team. The only difference we had to make was to change from `USER 1001` to `USER 1000`.

The main goal of the kerberos sidecar is to allow for authentication to services(mainly currently SQL IaaS Databases) demanding something compliant with Windows Authentication.

## Mutating the Pod
This webhook intercepts `pod` create requests and will `jsonpatch` the spec. Whether or not to mutate the pod spec happens in the `mutate` function. If the user namespace does not have the `kerberos-sidecar-injection` label, does not have a `kerberos-keytab` secret, or the pod does not have the `notebook-name` label present, then it will **not** mutate and `inject` the kerberos sidecars.

## Creating the jsonpatch
This is all done in the `createPatch` function. The very first thing that is done is determine if the pod _already has a volume_. This is because we do not want to overwrite any existing volumes in the `jsonpatch` as adding a new entry is very different from appending one.
From there, we don't really do any manipulations to the template stored in the `kerberos-sidecar-injector-json` configMap. Since every pod that gets injected will all share the exact same specs for the sidecar, there is no need for any configurations to change from the default.

### Getting the values to use in the json patch
For the sidecar spec, we have to use the `kerberos-sidecar-injector-json` configmap object from the `das` namespace. This works as the model / structure that we inject into the `pod` spec. 

### Inserting the values
Using the json template that we deep copy (to avoid modifying the same one over and over again and thus only getting the last changes), we call various `addX` or `updateX` functions whose only purpose is to return a `[]patchOperation`. These are self explanatory but we will note any exceptional cases below.

### updateWorkingVolumeMounts
This function adds the necessary volume mounts to the user container spec. To determine if we are modifying the correct container, we use the `NB_PREFIX` environment variable that should be present in the container specs. If you are testing with a podspec, ensure this variable is present. 

## For testing
Create a PR with the `auto-deploy` label, and after the image has successfully pushed to the ACR, go to the `kerberos` application in das argocd, turn off autosync (if it is on) and update the `kerberos-sidecar-injector` image tag with the pushed image tag. Start up a notebook and ensure it patches correctly.

## Building and Deploying
Once your PR is merged and the workflows are completed, take the SHA tag for the newly built image, and update the tag for the deployment for the kerberos-sidecar-injector in our gitlab [aaw-argocd-manifests](https://gitlab.k8s.cloud.statcan.ca/business-transformation/aaw/aaw-argocd-manifests) repo.

## Kerberos Sidecar Volumes
There are 3 volume mounts needed for the kerberos sidecar to function as expected:
- `kerberos-credential-cache` which is set up as an `emptyDir` and is used to store the cached results of the authentication
- `kerberos-conf` which is generated from the `kerberos-sidecar-config` configMap, which gets created in the user's namespace by our kerberos controller. It stores the configurations for the sidecar
- `kerberos-keytab` which is generated from the secret of the same name in the user's namespace which gets created by running the `ktutil-keytab` script from a running notebook. It gets used by the sidecar as the authentication token

## Related Components
The [kerberos controller](https://github.com/StatCan/aaw-kubeflow-profiles-controller/blob/profiles-controller-aaw2.0/cmd/kerberos.go) is setup to create the necessary components for the kerberos sidecar container to work as expected. When a user creates a "kerberos-keytab" secret in their namespace, with the use of our custom `ktutil-keytab` script defined in our [container images repo](https://github.com/StatCan/zone-kubeflow-containers/blob/master/resources/common/ktutil-keytab.sh), the controller should pick up this change in the user's namespace and create two resources:
- a `kerberos-sidecar-config` configMap to store the configurations for the sidecar
- a `allow-egress-to-kerberos-kdc` networkPolicy to allow connections from the sidecar to the needed service(Keytab Distribution Center).
