package kubernetes

import (
	"testing"

	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"

	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/mocks"
)

func TestKubernetesListResourcesByNamespace(t *testing.T) {
	mockWapcClient := &mocks.MockWapcClient{}

	expectedInputPayload := `{"api_version":"v1","kind":"Pod","namespace":"default","label_selector":"app=nginx","field_selector":"status.phase=Running"}`

	mockWapcClient.
		EXPECT().
		HostCall("kubewarden", "kubernetes", "list_resources_by_namespace", []byte(expectedInputPayload)).
		Return([]byte{}, nil).
		Times(1)

	host := &capabilities.Host{
		Client: mockWapcClient,
	}

	labelSelector := "app=nginx"
	fieldSelector := "status.phase=Running"

	inputRequest := ListResourcesByNamespaceRequest{
		APIVersion:    "v1",
		Kind:          "Pod",
		Namespace:     "default",
		LabelSelector: &labelSelector,
		FieldSelector: &fieldSelector,
	}

	_, err := ListResourcesByNamespace(host, inputRequest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestKubernetesListResources(t *testing.T) {
	mockWapcClient := &mocks.MockWapcClient{}

	expectedInputPayload := `{"api_version":"v1","kind":"Pod","label_selector":"app=nginx","field_selector":"status.phase=Running"}`

	mockWapcClient.
		EXPECT().
		HostCall("kubewarden", "kubernetes", "list_resources_all", []byte(expectedInputPayload)).
		Return([]byte{}, nil).
		Times(1)

	host := &capabilities.Host{
		Client: mockWapcClient,
	}

	labelSelector := "app=nginx"
	fieldSelector := "status.phase=Running"

	inputRequest := ListAllResourcesRequest{
		APIVersion:    "v1",
		Kind:          "Pod",
		LabelSelector: &labelSelector,
		FieldSelector: &fieldSelector,
	}

	_, err := ListResources(host, inputRequest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestKubernetesGetResource(t *testing.T) {
	mockWapcClient := &mocks.MockWapcClient{}

	expectedInputPayload := `{"api_version":"v1","kind":"Pod","name":"nginx","namespace":"default","disable_cache":false}`

	mockWapcClient.
		EXPECT().
		HostCall("kubewarden", "kubernetes", "get_resource", []byte(expectedInputPayload)).
		Return([]byte{}, nil).
		Times(1)

	host := &capabilities.Host{
		Client: mockWapcClient,
	}
	namespace := "default"
	inputRequest := GetResourceRequest{
		APIVersion:   "v1",
		Kind:         "Pod",
		Namespace:    &namespace,
		Name:         "nginx",
		DisableCache: false,
	}

	_, err := GetResource(host, inputRequest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestKubernetesCanI(t *testing.T) {
	mockWapcClient := &mocks.MockWapcClient{}

	expectedInputPayload := `{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"resourceAttributes":{"namespace":"default","verb":"get","group":"","resource":"pods"},"user":"jane.doe@example.com","groups":["developers"]},"disable_cache":false}`
	expectedResponse := []byte(`{"allowed":true,"denied":false,"reason":"User is authorized","evaluationError":""}`)
	mockWapcClient.
		EXPECT().
		HostCall("kubewarden", "kubernetes", "can_i", []byte(expectedInputPayload)).
		Return(expectedResponse, nil).
		Times(1)

	host := &capabilities.Host{
		Client: mockWapcClient,
	}
	inputRequest := SubjectAccessReviewRequest{
		APIVersion: "authorization.k8s.io/v1",
		Kind:       "SubjectAccessReview",
		Spec: SubjectAccessReviewSpec{
			ResourceAttributes: ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Group:     "",
				Resource:  "pods",
			},
			User:   "jane.doe@example.com",
			Groups: []string{"developers"},
		},
		DisableCache: false,
	}

	_, err := CanI(host, inputRequest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
