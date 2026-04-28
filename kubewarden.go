// This package provides helper functions and structs for writing
// https://kubewarden.io policies using the Go programming
// language.
package sdk

import (
	"encoding/json"
	"errors"

	appsv1 "github.com/kubewarden/k8s-objects/api/apps/v1"
	batchv1 "github.com/kubewarden/k8s-objects/api/batch/v1"
	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	"github.com/kubewarden/policy-sdk-go/protocol"
)

// Message is the optional string used to build validation responses.
type Message string

// Code is the optional error code associated with validation responses.
type Code uint16

const (
	// NoMessage can be used when building a response that doesn't have any
	// message to be shown to the user.
	NoMessage Message = ""

	// NoCode can be used when building a response that doesn't have any
	// error code to be shown to the user.
	NoCode Code = 0
)

const supportedPodSpecObjects = "apps/v1 Deployment, " +
	"apps/v1 ReplicaSet, apps/v1 StatefulSet, apps/v1 DaemonSet, v1 ReplicationController, " +
	"batch/v1 Job, batch/v1 CronJob, v1 Pod"

const supportedPodSpecObjectsMessage = "Object should be one of these group/version/kinds: " + supportedPodSpecObjects

const supportedPodSpecObjectsErrorMessage = "object should be one of these group/version/kinds: " + supportedPodSpecObjects

var errUnsupportedPodSpecObject = errors.New(supportedPodSpecObjectsErrorMessage)

// AcceptRequest can be used inside of the `validate` function to accept the
// incoming request.
func AcceptRequest() ([]byte, error) {
	response := protocol.ValidationResponse{
		Accepted: true,
	}

	return json.Marshal(response)
}

// RejectRequest can be used inside of the `validate` function to reject the
// incoming request
// * `message`: optional message to show to the user
// * `code`: optional error code to show to the user.
func RejectRequest(message Message, code Code) ([]byte, error) {
	response := protocol.ValidationResponse{
		Accepted: false,
	}
	if message != NoMessage {
		msg := string(message)
		response.Message = &msg
	}
	if code != NoCode {
		c := uint16(code)
		response.Code = &c
	}

	return json.Marshal(response)
}

// MutateRequest accepts the request and mutate the final object to match the
// one provided via the `newObject` param.
func MutateRequest(newObject interface{}) ([]byte, error) {
	response := protocol.ValidationResponse{
		Accepted:      true,
		MutatedObject: newObject,
	}

	return json.Marshal(response)
}

func isV1GroupKind(gvk protocol.GroupVersionKind, group, kind string) bool {
	return gvk.Group == group && gvk.Version == "v1" && gvk.Kind == kind
}

type podSpecTarget struct {
	object  interface{}
	podSpec **corev1.PodSpec
}

func (target podSpecTarget) podSpecValue() corev1.PodSpec {
	return **target.podSpec
}

func (target podSpecTarget) replacePodSpec(podSpec corev1.PodSpec) {
	*target.podSpec = &podSpec
}

func missingPodSpecError(kind string) error {
	return errors.New(kind + " object does not contain a PodSpec")
}

func podSpecFromTemplate(kind string, template *corev1.PodTemplateSpec) (*corev1.PodSpec, error) {
	if template == nil || template.Spec == nil {
		return nil, missingPodSpecError(kind)
	}

	return template.Spec, nil
}

func podSpecTargetFromTemplate(kind string, object interface{}, template *corev1.PodTemplateSpec) (podSpecTarget, error) {
	if _, err := podSpecFromTemplate(kind, template); err != nil {
		return podSpecTarget{}, err
	}

	return podSpecTarget{
		object:  object,
		podSpec: &template.Spec,
	}, nil
}

func deploymentPodSpecTarget(rawObject json.RawMessage) (podSpecTarget, error) {
	deployment := appsv1.Deployment{}
	if err := json.Unmarshal(rawObject, &deployment); err != nil {
		return podSpecTarget{}, err
	}
	if deployment.Spec == nil {
		return podSpecTarget{}, missingPodSpecError("Deployment")
	}

	return podSpecTargetFromTemplate("Deployment", &deployment, deployment.Spec.Template)
}

func replicaSetPodSpecTarget(rawObject json.RawMessage) (podSpecTarget, error) {
	replicaset := appsv1.ReplicaSet{}
	if err := json.Unmarshal(rawObject, &replicaset); err != nil {
		return podSpecTarget{}, err
	}
	if replicaset.Spec == nil {
		return podSpecTarget{}, missingPodSpecError("ReplicaSet")
	}

	return podSpecTargetFromTemplate("ReplicaSet", &replicaset, replicaset.Spec.Template)
}

func statefulSetPodSpecTarget(rawObject json.RawMessage) (podSpecTarget, error) {
	statefulset := appsv1.StatefulSet{}
	if err := json.Unmarshal(rawObject, &statefulset); err != nil {
		return podSpecTarget{}, err
	}
	if statefulset.Spec == nil {
		return podSpecTarget{}, missingPodSpecError("StatefulSet")
	}

	return podSpecTargetFromTemplate("StatefulSet", &statefulset, statefulset.Spec.Template)
}

func daemonSetPodSpecTarget(rawObject json.RawMessage) (podSpecTarget, error) {
	daemonset := appsv1.DaemonSet{}
	if err := json.Unmarshal(rawObject, &daemonset); err != nil {
		return podSpecTarget{}, err
	}
	if daemonset.Spec == nil {
		return podSpecTarget{}, missingPodSpecError("DaemonSet")
	}

	return podSpecTargetFromTemplate("DaemonSet", &daemonset, daemonset.Spec.Template)
}

func replicationControllerPodSpecTarget(rawObject json.RawMessage) (podSpecTarget, error) {
	replicationController := corev1.ReplicationController{}
	if err := json.Unmarshal(rawObject, &replicationController); err != nil {
		return podSpecTarget{}, err
	}
	if replicationController.Spec == nil {
		return podSpecTarget{}, missingPodSpecError("ReplicationController")
	}

	return podSpecTargetFromTemplate("ReplicationController", &replicationController, replicationController.Spec.Template)
}

func cronJobPodSpecTarget(rawObject json.RawMessage) (podSpecTarget, error) {
	cronjob := batchv1.CronJob{}
	if err := json.Unmarshal(rawObject, &cronjob); err != nil {
		return podSpecTarget{}, err
	}
	if cronjob.Spec == nil || cronjob.Spec.JobTemplate == nil || cronjob.Spec.JobTemplate.Spec == nil {
		return podSpecTarget{}, missingPodSpecError("CronJob")
	}

	return podSpecTargetFromTemplate("CronJob", &cronjob, cronjob.Spec.JobTemplate.Spec.Template)
}

func jobPodSpecTarget(rawObject json.RawMessage) (podSpecTarget, error) {
	job := batchv1.Job{}
	if err := json.Unmarshal(rawObject, &job); err != nil {
		return podSpecTarget{}, err
	}
	if job.Spec == nil {
		return podSpecTarget{}, missingPodSpecError("Job")
	}

	return podSpecTargetFromTemplate("Job", &job, job.Spec.Template)
}

func podPodSpecTarget(rawObject json.RawMessage) (podSpecTarget, error) {
	pod := corev1.Pod{}
	if err := json.Unmarshal(rawObject, &pod); err != nil {
		return podSpecTarget{}, err
	}
	if pod.Spec == nil {
		return podSpecTarget{}, missingPodSpecError("Pod")
	}

	return podSpecTarget{
		object:  &pod,
		podSpec: &pod.Spec,
	}, nil
}

func podSpecTargetFromRequest(validationRequest protocol.ValidationRequest) (podSpecTarget, error) {
	gvk := validationRequest.Request.Kind
	switch {
	case isV1GroupKind(gvk, appsv1.GroupName, "Deployment"):
		return deploymentPodSpecTarget(validationRequest.Request.Object)
	case isV1GroupKind(gvk, appsv1.GroupName, "ReplicaSet"):
		return replicaSetPodSpecTarget(validationRequest.Request.Object)
	case isV1GroupKind(gvk, appsv1.GroupName, "StatefulSet"):
		return statefulSetPodSpecTarget(validationRequest.Request.Object)
	case isV1GroupKind(gvk, appsv1.GroupName, "DaemonSet"):
		return daemonSetPodSpecTarget(validationRequest.Request.Object)
	case isV1GroupKind(gvk, corev1.GroupName, "ReplicationController"):
		return replicationControllerPodSpecTarget(validationRequest.Request.Object)
	case isV1GroupKind(gvk, batchv1.GroupName, "CronJob"):
		return cronJobPodSpecTarget(validationRequest.Request.Object)
	case isV1GroupKind(gvk, batchv1.GroupName, "Job"):
		return jobPodSpecTarget(validationRequest.Request.Object)
	case isV1GroupKind(gvk, corev1.GroupName, "Pod"):
		return podPodSpecTarget(validationRequest.Request.Object)
	default:
		return podSpecTarget{}, errUnsupportedPodSpecObject
	}
}

// MutatePodSpecFromRequest updates the pod spec from the resource defined in the original object and
// create an acceptance response.
// * `validation_request` - the original admission request
// * `pod_spec` - new PodSpec to be set in the response.
func MutatePodSpecFromRequest(validationRequest protocol.ValidationRequest, podSpec corev1.PodSpec) ([]byte, error) {
	target, err := podSpecTargetFromRequest(validationRequest)
	if errors.Is(err, errUnsupportedPodSpecObject) {
		return RejectRequest(supportedPodSpecObjectsMessage, NoCode)
	}
	if err != nil {
		return nil, err
	}

	target.replacePodSpec(podSpec)
	return MutateRequest(target.object)
}

// AcceptSettings can be used inside of the `validate_settings` function to
// mark the user provided settings as valid.
func AcceptSettings() ([]byte, error) {
	response := protocol.SettingsValidationResponse{
		Valid: true,
	}
	return json.Marshal(response)
}

// RejectSettings can be used inside of the `validate_settings` function to
// mark the user provided settings as invalid
// * `message`: optional message to show to the user.
func RejectSettings(message Message) ([]byte, error) {
	response := protocol.SettingsValidationResponse{
		Valid: false,
	}

	if message != NoMessage {
		msg := string(message)
		response.Message = &msg
	}
	return json.Marshal(response)
}

// ExtractPodSpecFromObject extracts the PodSpec from high level objects.
// This method can be used to evaluate high level objects instead of just Pods.
// For example, it can be used to reject Deployments or StatefulSets
// that violate a policy instead of the Pods created by them.
// Objects supported are: Deployment, ReplicaSet, StatefulSet,
// DaemonSet, ReplicationController, Job, CronJob, Pod It returns an error if
// the object is not one of those or does not contain a PodSpec.
// * `object`: the request to validate.
func ExtractPodSpecFromObject(object protocol.ValidationRequest) (corev1.PodSpec, error) {
	target, err := podSpecTargetFromRequest(object)
	if err != nil {
		return corev1.PodSpec{}, err
	}

	return target.podSpecValue(), nil
}
