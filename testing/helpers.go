package testing

import (
	"errors"
	"os"

	appsv1 "github.com/kubewarden/k8s-objects/api/apps/v1"
	batchv1 "github.com/kubewarden/k8s-objects/api/batch/v1"
	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	"github.com/mailru/easyjson"
)

// BuildValidationRequestFromFixture creates the payload for the invocation of the `validate`
// function.
// * `req_fixture`: path to the json file with a recorded requst to evaluate
// * `settings`: instance of policy settings. Must be serializable to JSON using easyjson
func BuildValidationRequestFromFixture(req_fixture string, settings easyjson.Marshaler) ([]byte, error) {
	kubeAdmissionReqRaw, err := os.ReadFile(req_fixture)
	if err != nil {
		return nil, err
	}

	kubeAdmissionReq := kubewarden_protocol.KubernetesAdmissionRequest{}
	if err := easyjson.Unmarshal(kubeAdmissionReqRaw, &kubeAdmissionReq); err != nil {
		return nil, err
	}

	settingsRaw, err := easyjson.Marshal(settings)
	if err != nil {
		return nil, err
	}

	validationRequest := kubewarden_protocol.ValidationRequest{
		Request:  kubeAdmissionReq,
		Settings: settingsRaw,
	}

	return easyjson.Marshal(validationRequest)
}

// BuildValidationRequest creates the payload for the invocation of the `validate`
// function.
// * `object`: instance of the object. Must be serializable to JSON using easyjson
// * `settings`: instance of policy settings. Must be serializable to JSON using easyjson
func BuildValidationRequest(object, settings easyjson.Marshaler) ([]byte, error) {
	objectRaw, err := easyjson.Marshal(object)
	if err != nil {
		return nil, err
	}

	kubeAdmissionReq := kubewarden_protocol.KubernetesAdmissionRequest{
		Object: objectRaw,
	}

	settingsRaw, err := easyjson.Marshal(settings)
	if err != nil {
		return nil, err
	}

	validationRequest := kubewarden_protocol.ValidationRequest{
		Request:  kubeAdmissionReq,
		Settings: settingsRaw,
	}

	return easyjson.Marshal(validationRequest)
}

// Extract PodSpec from high level objects. This method can be used to evaluate high level objects instead of just Pods.
// For example, it can be used to reject Deployments or StatefulSets that violate a policy instead of the Pods created by them.
// Objects supported are: Deployment, ReplicaSet, StatefulSet, DaemonSet, ReplicationController, Job, CronJob, Pod
// It returns an error if the object is not one of those. If it is a supported object it returns the PodSpec if present, otherwise returns None.
func ExtractPodSpecFromObject(object kubewarden_protocol.ValidationRequest) (corev1.PodSpec, error) {
	switch object.Request.Kind.Kind {
	case "Deployment":
		deployment := &appsv1.Deployment{}
		if err := easyjson.Unmarshal(object.Request.Object, deployment); err != nil {
			return corev1.PodSpec{}, err
		}
		return *deployment.Spec.Template.Spec, nil
	case "ReplicaSet":
		replicaset := &appsv1.ReplicaSet{}
		if err := easyjson.Unmarshal(object.Request.Object, replicaset); err != nil {
			return corev1.PodSpec{}, err
		}
		return *replicaset.Spec.Template.Spec, nil
	case "StatefulSet":
		statefulset := &appsv1.StatefulSet{}
		if err := easyjson.Unmarshal(object.Request.Object, statefulset); err != nil {
			return corev1.PodSpec{}, err
		}
		return *statefulset.Spec.Template.Spec, nil
	case "DaemonSet":
		daemonset := &appsv1.DaemonSet{}
		if err := easyjson.Unmarshal(object.Request.Object, daemonset); err != nil {
			return corev1.PodSpec{}, err
		}
		return *daemonset.Spec.Template.Spec, nil
	case "ReplicationController":
		replication_controller := &corev1.ReplicationController{}
		if err := easyjson.Unmarshal(object.Request.Object, replication_controller); err != nil {
			return corev1.PodSpec{}, err
		}
		return *replication_controller.Spec.Template.Spec, nil
	case "CronJob":
		cronjob := &batchv1.CronJob{}
		if err := easyjson.Unmarshal(object.Request.Object, cronjob); err != nil {
			return corev1.PodSpec{}, err
		}
		return *cronjob.Spec.JobTemplate.Spec.Template.Spec, nil
	case "Job":
		job := &batchv1.Job{}
		if err := easyjson.Unmarshal(object.Request.Object, job); err != nil {
			return corev1.PodSpec{}, err
		}
		return *job.Spec.Template.Spec, nil
	case "Pod":
		pod := &corev1.Pod{}
		if err := easyjson.Unmarshal(object.Request.Object, pod); err != nil {
			return corev1.PodSpec{}, err
		}
		return *pod.Spec, nil
	default:
		return corev1.PodSpec{}, errors.New("object should be one of these kinds: Deployment, ReplicaSet, StatefulSet, DaemonSet, ReplicationController, Job, CronJob, Pod")
	}
}
