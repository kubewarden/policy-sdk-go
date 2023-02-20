package sdk

import (
	"testing"

	appsv1 "github.com/kubewarden/k8s-objects/api/apps/v1"
	batchv1 "github.com/kubewarden/k8s-objects/api/batch/v1"
	corev1 "github.com/kubewarden/k8s-objects/api/core/v1"
	"github.com/kubewarden/policy-sdk-go/protocol"
	"github.com/mailru/easyjson"
	"github.com/mailru/easyjson/jwriter"
)

func CreateValidationRequest(object easyjson.Marshaler, kind string) (protocol.ValidationRequest, error) {
	w := jwriter.Writer{}
	object.MarshalEasyJSON(&w)
	value, err := w.BuildBytes()
	if err != nil {
		return protocol.ValidationRequest{}, err
	}

	validationRequest := protocol.ValidationRequest{
		Settings: easyjson.RawMessage{},
		Request: protocol.KubernetesAdmissionRequest{
			Kind: protocol.GroupVersionKind{
				Kind: kind,
			},
			Object: value,
		},
	}

	return validationRequest, nil
}

func CheckIfAutomountServiceAccountTokenIsTrue(t *testing.T, rawResponse []byte) protocol.ValidationResponse {
	response := protocol.ValidationResponse{}
	if err := easyjson.Unmarshal(rawResponse, &response); err != nil {
		t.Fatalf("Error: %v", err)
	}

	if !response.Accepted {
		t.Fatalf("Response not accepted")
	}

	if len(response.MutatedObject.(map[string]interface{})) == 0 {
		t.Fatalf("Request should be mutated")
	}

	return response
}

func TestMutatePodSpecFromRequestWithDeployment(t *testing.T) {
	deployment := appsv1.Deployment{
		Spec: &appsv1.DeploymentSpec{
			Template: &corev1.PodTemplateSpec{
				Spec: &corev1.PodSpec{
					AutomountServiceAccountToken: false,
				},
			},
		},
	}

	validationRequest, err := CreateValidationRequest(deployment, "apps.v1.Deployment")
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

	response := CheckIfAutomountServiceAccountTokenIsTrue(t, rawResponse)

	if response.MutatedObject.(map[string]interface{})["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})["automountServiceAccountToken"].(bool) != true {
		t.Fatalf("Request not mutated")
	}
}

func TestMutatePodSpecFromRequestWithReplicaset(t *testing.T) {
	replicaset := appsv1.ReplicaSet{
		Spec: &appsv1.ReplicaSetSpec{
			Template: &corev1.PodTemplateSpec{
				Spec: &corev1.PodSpec{
					AutomountServiceAccountToken: false,
				},
			},
		},
	}

	validationRequest, err := CreateValidationRequest(replicaset, "apps.v1.ReplicaSet")
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

	response := CheckIfAutomountServiceAccountTokenIsTrue(t, rawResponse)

	if response.MutatedObject.(map[string]interface{})["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})["automountServiceAccountToken"].(bool) != true {
		t.Fatalf("Request not mutated")
	}
}

func TestMutatePodSpecFromRequestWithStatefulset(t *testing.T) {
	statefulset := appsv1.StatefulSet{
		Spec: &appsv1.StatefulSetSpec{
			Template: &corev1.PodTemplateSpec{
				Spec: &corev1.PodSpec{
					AutomountServiceAccountToken: false,
				},
			},
		},
	}

	validationRequest, err := CreateValidationRequest(statefulset, "apps.v1.StatefulSet")
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

	response := CheckIfAutomountServiceAccountTokenIsTrue(t, rawResponse)

	if response.MutatedObject.(map[string]interface{})["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})["automountServiceAccountToken"].(bool) != true {
		t.Fatalf("Request not mutated")
	}
}

func TestMutatePodSpecFromRequestWithDaemonset(t *testing.T) {
	daemonset := appsv1.DaemonSet{
		Spec: &appsv1.DaemonSetSpec{
			Template: &corev1.PodTemplateSpec{
				Spec: &corev1.PodSpec{
					AutomountServiceAccountToken: false,
				},
			},
		},
	}

	validationRequest, err := CreateValidationRequest(daemonset, "apps.v1.DaemonSet")
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

	response := CheckIfAutomountServiceAccountTokenIsTrue(t, rawResponse)

	if response.MutatedObject.(map[string]interface{})["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})["automountServiceAccountToken"].(bool) != true {
		t.Fatalf("Request not mutated")
	}
}

func TestMutatePodSpecFromRequestWithReplicationcontroller(t *testing.T) {
	replicationController := corev1.ReplicationController{
		Spec: &corev1.ReplicationControllerSpec{
			Template: &corev1.PodTemplateSpec{
				Spec: &corev1.PodSpec{
					AutomountServiceAccountToken: false,
				},
			},
		},
	}

	validationRequest, err := CreateValidationRequest(replicationController, "v1.ReplicationController")
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

	response := CheckIfAutomountServiceAccountTokenIsTrue(t, rawResponse)

	if response.MutatedObject.(map[string]interface{})["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})["automountServiceAccountToken"].(bool) != true {
		t.Fatalf("Request not mutated")
	}
}

func TestMutatePodSpecFromRequestWithCronjob(t *testing.T) {
	cronjob := batchv1.CronJob{
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
	}

	validationRequest, err := CreateValidationRequest(cronjob, "batch.v1.CronJob")
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

	response := CheckIfAutomountServiceAccountTokenIsTrue(t, rawResponse)

	if response.MutatedObject.(map[string]interface{})["spec"].(map[string]interface{})["jobTemplate"].(map[string]interface{})["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})["automountServiceAccountToken"].(bool) != true {
		t.Fatalf("Request not mutated")
	}
}

func TestMutatePodSpecFromRequestWithJob(t *testing.T) {
	job := batchv1.Job{
		Spec: &batchv1.JobSpec{
			Template: &corev1.PodTemplateSpec{
				Spec: &corev1.PodSpec{
					AutomountServiceAccountToken: false,
				},
			},
		},
	}

	validationRequest, err := CreateValidationRequest(job, "batch.v1.Job")
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

	response := CheckIfAutomountServiceAccountTokenIsTrue(t, rawResponse)

	if response.MutatedObject.(map[string]interface{})["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})["automountServiceAccountToken"].(bool) != true {
		t.Fatalf("Request not mutated")
	}
}

func TestMutatePodSpecFromRequestWithPod(t *testing.T) {
	pod := &corev1.Pod{
		Spec: &corev1.PodSpec{
			AutomountServiceAccountToken: false,
		},
	}

	validationRequest, err := CreateValidationRequest(pod, "v1.Pod")
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

	response := CheckIfAutomountServiceAccountTokenIsTrue(t, rawResponse)

	if response.MutatedObject.(map[string]interface{})["spec"].(map[string]interface{})["automountServiceAccountToken"].(bool) != true {
		t.Fatalf("Request not mutated")
	}
}

func TestMutatePodSpecFromRequestWithInvalidResourceType(t *testing.T) {
	pod := &corev1.Pod{}

	validationRequest, err := CreateValidationRequest(pod, "InvalidType")
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
	if err := easyjson.Unmarshal(rawResponse, &response); err != nil {
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
