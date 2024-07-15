package sdk

import (
	"encoding/json"
	"errors"
	"testing"

	appsv1 "github.com/kubewarden/k8s-objects/api/apps/v1"
	batchv1 "github.com/kubewarden/k8s-objects/api/batch/v1"
	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	"github.com/kubewarden/policy-sdk-go/protocol"
)

type mutatePodSpecFromRequestTestCase struct {
	kind              string
	object            interface{}
	mutatedObject     interface{}
	mutationCheckFunc func(t interface{}) bool
}

func createValidationRequest(object interface{}, kind string) (protocol.ValidationRequest, error) {
	value, err := json.Marshal(&object)

	if err != nil {
		return protocol.ValidationRequest{}, err
	}

	validationRequest := protocol.ValidationRequest{
		Settings: json.RawMessage{},
		Request: protocol.KubernetesAdmissionRequest{
			Kind: protocol.GroupVersionKind{
				Kind: kind,
			},
			Object: value,
		},
	}

	return validationRequest, nil
}

// Build a ValidationResponse object. Returns an error if the validation
// response is not accepted and the incoming object has not been mutated.
func CheckIfAutomountServiceAccountTokenIsTrue(rawResponse []byte, mutatedObject interface{}) error {
	response := protocol.ValidationResponse{
		MutatedObject: mutatedObject,
	}
	if err := json.Unmarshal(rawResponse, &response); err != nil {
		return err
	}

	if !response.Accepted {
		return errors.New("Response not accepted")
	}

	if response.MutatedObject == nil {
		return errors.New("Request not mutated")
	}

	return nil
}

func TestMutatePodSpecFromRequest(t *testing.T) {
	mutatedDeployment := &appsv1.Deployment{}
	mutatedReplicaset := &appsv1.ReplicaSet{}
	mutatedStatefulset := &appsv1.StatefulSet{}
	mutatedDaemonset := &appsv1.DaemonSet{}
	mutatedReplicationController := &corev1.ReplicationController{}
	mutatedCronjob := &batchv1.CronJob{}
	mutatedJob := &batchv1.Job{}
	mutatedPod := &corev1.Pod{}

	for description, testCase := range map[string]mutatePodSpecFromRequestTestCase{
		"WithDeployment": {
			kind: "Deployment",
			object: appsv1.Deployment{
				Spec: &appsv1.DeploymentSpec{
					Template: &corev1.PodTemplateSpec{
						Spec: &corev1.PodSpec{
							AutomountServiceAccountToken: false,
						},
					},
				},
			},
			mutatedObject:     mutatedDeployment,
			mutationCheckFunc: CheckPodSpecMutatedFromRequestWithDeployment,
		},
		"WithReplicaset": {
			kind: "ReplicaSet",
			object: appsv1.ReplicaSet{
				Spec: &appsv1.ReplicaSetSpec{
					Template: &corev1.PodTemplateSpec{
						Spec: &corev1.PodSpec{
							AutomountServiceAccountToken: false,
						},
					},
				},
			},
			mutatedObject:     mutatedReplicaset,
			mutationCheckFunc: CheckPodSpecMutatedFromRequestWithReplicaset,
		},
		"WithStatefulset": {
			kind: "StatefulSet",
			object: appsv1.StatefulSet{
				Spec: &appsv1.StatefulSetSpec{
					Template: &corev1.PodTemplateSpec{
						Spec: &corev1.PodSpec{
							AutomountServiceAccountToken: false,
						},
					},
				},
			},
			mutatedObject:     mutatedStatefulset,
			mutationCheckFunc: CheckPodSpecMutatedFromRequestWithStatefulset,
		},
		"WithDaemonset": {
			kind: "DaemonSet",
			object: appsv1.DaemonSet{
				Spec: &appsv1.DaemonSetSpec{
					Template: &corev1.PodTemplateSpec{
						Spec: &corev1.PodSpec{
							AutomountServiceAccountToken: false,
						},
					},
				},
			},
			mutatedObject:     mutatedDaemonset,
			mutationCheckFunc: CheckPodSpecMutatedFromRequestWithDaemonset,
		},
		"WithReplicationcontroller": {
			kind: "ReplicationController",
			object: corev1.ReplicationController{
				Spec: &corev1.ReplicationControllerSpec{
					Template: &corev1.PodTemplateSpec{
						Spec: &corev1.PodSpec{
							AutomountServiceAccountToken: false,
						},
					},
				},
			},
			mutatedObject:     mutatedReplicationController,
			mutationCheckFunc: CheckPodSpecMutatedFromRequestWithReplicationcontroller,
		},
		"WithCronjob": {
			kind: "CronJob",
			object: batchv1.CronJob{
				Spec: &batchv1.CronJobSpec{
					JobTemplate: &batchv1.JobTemplateSpec{
						Spec: &batchv1.JobSpec{
							Template: &corev1.PodTemplateSpec{
								Spec: &corev1.PodSpec{
									AutomountServiceAccountToken: false,
								},
							},
						},
					},
				},
			},
			mutatedObject:     mutatedCronjob,
			mutationCheckFunc: CheckPodSpecMutatedFromRequestWithCronjob,
		},
		"WithJob": {
			kind: "Job",
			object: batchv1.Job{
				Spec: &batchv1.JobSpec{
					Template: &corev1.PodTemplateSpec{
						Spec: &corev1.PodSpec{
							AutomountServiceAccountToken: false,
						},
					},
				},
			},
			mutatedObject:     mutatedJob,
			mutationCheckFunc: CheckPodSpecMutatedFromRequestWithJob,
		},
		"WithPod": {
			kind: "Pod",
			object: corev1.Pod{
				Spec: &corev1.PodSpec{
					AutomountServiceAccountToken: false,
				},
			},
			mutatedObject:     mutatedPod,
			mutationCheckFunc: CheckPodSpecMutatedFromRequestWithPod,
		},
	} {
		t.Run(description, func(t *testing.T) {
			validationRequest, err := createValidationRequest(testCase.object, testCase.kind)
			if err != nil {
				t.Fatalf("Error: %v", err)
			}

			newPodSpec := corev1.PodSpec{
				AutomountServiceAccountToken: true,
			}

			rawResponse, err := MutatePodSpecFromRequest(validationRequest, newPodSpec)
			if err != nil {
				t.Fatalf("Error: %v", err)
			}

			if err = CheckIfAutomountServiceAccountTokenIsTrue(rawResponse, testCase.mutatedObject); err != nil {
				t.Fatalf("Error: %v", err)
			}

			if !testCase.mutationCheckFunc(testCase.mutatedObject) {
				t.Fatalf("Request not mutated")
			}
		})
	}
}

func CheckPodSpecMutatedFromRequestWithDeployment(object interface{}) bool {
	return object.(*appsv1.Deployment).Spec.Template.Spec.AutomountServiceAccountToken == true
}

func CheckPodSpecMutatedFromRequestWithReplicaset(object interface{}) bool {
	return object.(*appsv1.ReplicaSet).Spec.Template.Spec.AutomountServiceAccountToken == true
}

func CheckPodSpecMutatedFromRequestWithStatefulset(object interface{}) bool {
	return object.(*appsv1.StatefulSet).Spec.Template.Spec.AutomountServiceAccountToken == true
}

func CheckPodSpecMutatedFromRequestWithDaemonset(object interface{}) bool {
	return object.(*appsv1.DaemonSet).Spec.Template.Spec.AutomountServiceAccountToken == true
}

func CheckPodSpecMutatedFromRequestWithReplicationcontroller(object interface{}) bool {
	return object.(*corev1.ReplicationController).Spec.Template.Spec.AutomountServiceAccountToken == true
}

func CheckPodSpecMutatedFromRequestWithCronjob(object interface{}) bool {
	return object.(*batchv1.CronJob).Spec.JobTemplate.Spec.Template.Spec.AutomountServiceAccountToken == true
}

func CheckPodSpecMutatedFromRequestWithJob(object interface{}) bool {
	return object.(*batchv1.Job).Spec.Template.Spec.AutomountServiceAccountToken == true
}

func CheckPodSpecMutatedFromRequestWithPod(object interface{}) bool {
	return object.(*corev1.Pod).Spec.AutomountServiceAccountToken == true
}
func TestMutatePodSpecFromRequestWithInvalidResourceType(t *testing.T) {
	pod := &corev1.Pod{}

	validationRequest, err := createValidationRequest(pod, "InvalidType")
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	newPodSpec := corev1.PodSpec{
		AutomountServiceAccountToken: true,
	}

	rawResponse, err := MutatePodSpecFromRequest(validationRequest, newPodSpec)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	response := protocol.ValidationResponse{}
	if err = json.Unmarshal(rawResponse, &response); err != nil {
		t.Fatalf("Error: %v", err)
	}

	if response.Accepted {
		t.Fatalf("Response accepted")
	}

	errorMessage := response.Message
	expectedErrorMessage := "Object should be one of these kinds: Deployment, ReplicaSet, StatefulSet, DaemonSet, ReplicationController, Job, CronJob, Pod"
	if *errorMessage != expectedErrorMessage {
		t.Fatalf("Different error occurred")
	}
}
