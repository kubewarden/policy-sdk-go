package kubernetes

import (
	"testing"

	"github.com/golang/mock/gomock"
	mock_capabilities "github.com/kubewarden/policy-sdk-go/mock/capabilities"
	cap "github.com/kubewarden/policy-sdk-go/pkg/capabilities"
)

func TestKubernetesListResourcesByNamespace(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock_capabilities.NewMockWapcClient(ctrl)

	expectedInputPayload := `{"api_version":"v1","kind":"Pod","namespace":"default","label_selector":"app=nginx","field_selector":"status.phase=Running"}`

	m.
		EXPECT().
		HostCall("kubewarden", "kubernetes", "list_resources_by_namespace", []byte(expectedInputPayload)).
		Return([]byte{}, nil).
		Times(1)

	host := &cap.Host{
		Client: m,
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
	ctrl := gomock.NewController(t)
	m := mock_capabilities.NewMockWapcClient(ctrl)

	expectedInputPayload := `{"api_version":"v1","kind":"Pod","label_selector":"app=nginx","field_selector":"status.phase=Running"}`

	m.
		EXPECT().
		HostCall("kubewarden", "kubernetes", "list_resources_all", []byte(expectedInputPayload)).
		Return([]byte{}, nil).
		Times(1)

	host := &cap.Host{
		Client: m,
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
	ctrl := gomock.NewController(t)
	m := mock_capabilities.NewMockWapcClient(ctrl)

	expectedInputPayload := `{"api_version":"v1","kind":"Pod","name":"nginx","namespace":"default","disable_cache":false}`

	m.
		EXPECT().
		HostCall("kubewarden", "kubernetes", "get_resource", []byte(expectedInputPayload)).
		Return([]byte{}, nil).
		Times(1)

	host := &cap.Host{
		Client: m,
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
