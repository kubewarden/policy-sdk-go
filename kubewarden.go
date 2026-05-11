// Package sdk provides helper functions and structs for writing
// https://kubewarden.io policies using the Go programming
// language.
package sdk

import (
	"encoding/json"
	"fmt"

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

	kindDeployment            = "Deployment"
	kindReplicaSet            = "ReplicaSet"
	kindStatefulSet           = "StatefulSet"
	kindDaemonSet             = "DaemonSet"
	kindReplicationController = "ReplicationController"
	kindCronJob               = "CronJob"
	kindJob                   = "Job"
	kindPod                   = "Pod"
)

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
func MutateRequest(newObject any) ([]byte, error) {
	response := protocol.ValidationResponse{
		Accepted:      true,
		MutatedObject: newObject,
	}

	return json.Marshal(response)
}

// MutatePodSpecFromRequest updates the pod spec from the resource defined in the original object and
// create an acceptance response.
// * `validation_request` - the original admission request
// * `pod_spec` - new PodSpec to be set in the response.
//
//nolint:funlen // Splitting this function would not make it more readable.
func MutatePodSpecFromRequest(validationRequest protocol.ValidationRequest, podSepc corev1.PodSpec) ([]byte, error) {
	switch validationRequest.Request.Kind.Kind {
	case kindDeployment:
		deployment := appsv1.Deployment{}
		if err := json.Unmarshal(validationRequest.Request.Object, &deployment); err != nil {
			return nil, err
		}
		deployment.Spec.Template.Spec = &podSepc
		return MutateRequest(deployment)
	case kindReplicaSet:
		replicaset := appsv1.ReplicaSet{}
		if err := json.Unmarshal(validationRequest.Request.Object, &replicaset); err != nil {
			return nil, err
		}
		replicaset.Spec.Template.Spec = &podSepc
		return MutateRequest(replicaset)
	case kindStatefulSet:
		statefulset := appsv1.StatefulSet{}
		if err := json.Unmarshal(validationRequest.Request.Object, &statefulset); err != nil {
			return nil, err
		}
		statefulset.Spec.Template.Spec = &podSepc
		return MutateRequest(statefulset)
	case kindDaemonSet:
		daemonset := appsv1.DaemonSet{}
		if err := json.Unmarshal(validationRequest.Request.Object, &daemonset); err != nil {
			return nil, err
		}
		daemonset.Spec.Template.Spec = &podSepc
		return MutateRequest(daemonset)
	case kindReplicationController:
		replicationController := corev1.ReplicationController{}
		if err := json.Unmarshal(validationRequest.Request.Object, &replicationController); err != nil {
			return nil, err
		}
		replicationController.Spec.Template.Spec = &podSepc
		return MutateRequest(replicationController)
	case kindCronJob:
		cronjob := batchv1.CronJob{}
		if err := json.Unmarshal(validationRequest.Request.Object, &cronjob); err != nil {
			return nil, err
		}
		cronjob.Spec.JobTemplate.Spec.Template.Spec = &podSepc
		return MutateRequest(cronjob)
	case kindJob:
		job := batchv1.Job{}
		if err := json.Unmarshal(validationRequest.Request.Object, &job); err != nil {
			return nil, err
		}
		job.Spec.Template.Spec = &podSepc
		return MutateRequest(job)
	case kindPod:
		pod := corev1.Pod{}
		if err := json.Unmarshal(validationRequest.Request.Object, &pod); err != nil {
			return nil, err
		}
		pod.Spec = &podSepc
		return MutateRequest(pod)
	default:
		return RejectRequest("Object should be one of these kinds: Deployment, "+
			"ReplicaSet, StatefulSet, DaemonSet, ReplicationController, Job, CronJob, Pod", NoCode)
	}
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
// the object is not one of those. If it is a supported object it returns the
// PodSpec if present, otherwise returns an empty PodSpec.
// * `object`: the request to validate.
func ExtractPodSpecFromObject(object protocol.ValidationRequest) (corev1.PodSpec, error) {
	switch object.Request.Kind.Kind {
	case kindDeployment:
		deployment := appsv1.Deployment{}
		if err := json.Unmarshal(object.Request.Object, &deployment); err != nil {
			return corev1.PodSpec{}, err
		}
		return *deployment.Spec.Template.Spec, nil
	case kindReplicaSet:
		replicaset := appsv1.ReplicaSet{}
		if err := json.Unmarshal(object.Request.Object, &replicaset); err != nil {
			return corev1.PodSpec{}, err
		}
		return *replicaset.Spec.Template.Spec, nil
	case kindStatefulSet:
		statefulset := appsv1.StatefulSet{}
		if err := json.Unmarshal(object.Request.Object, &statefulset); err != nil {
			return corev1.PodSpec{}, err
		}
		return *statefulset.Spec.Template.Spec, nil
	case kindDaemonSet:
		daemonset := appsv1.DaemonSet{}
		if err := json.Unmarshal(object.Request.Object, &daemonset); err != nil {
			return corev1.PodSpec{}, err
		}
		return *daemonset.Spec.Template.Spec, nil
	case kindReplicationController:
		replicationController := corev1.ReplicationController{}
		if err := json.Unmarshal(object.Request.Object, &replicationController); err != nil {
			return corev1.PodSpec{}, err
		}
		return *replicationController.Spec.Template.Spec, nil
	case kindCronJob:
		cronjob := batchv1.CronJob{}
		if err := json.Unmarshal(object.Request.Object, &cronjob); err != nil {
			return corev1.PodSpec{}, err
		}
		return *cronjob.Spec.JobTemplate.Spec.Template.Spec, nil
	case kindJob:
		job := batchv1.Job{}
		if err := json.Unmarshal(object.Request.Object, &job); err != nil {
			return corev1.PodSpec{}, err
		}
		return *job.Spec.Template.Spec, nil
	case kindPod:
		pod := corev1.Pod{}
		if err := json.Unmarshal(object.Request.Object, &pod); err != nil {
			return corev1.PodSpec{}, err
		}
		return *pod.Spec, nil
	default:
		return corev1.PodSpec{}, fmt.Errorf("object should be one of these kinds: %s, %s, %s, %s, %s, %s, %s, %s",
			kindDeployment, kindReplicaSet, kindStatefulSet, kindDaemonSet,
			kindReplicationController, kindJob, kindCronJob, kindPod)
	}
}
