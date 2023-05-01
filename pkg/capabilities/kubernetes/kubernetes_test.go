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

	expectedInputPayload := []byte{123, 34, 97, 112, 105, 95, 118, 101, 114, 115, 105, 111, 110, 34, 58, 34, 118, 49, 34, 44, 34, 107, 105, 110, 100, 34, 58, 34, 80, 111, 100, 34, 44, 34, 110, 97, 109, 101, 115, 112, 97, 99, 101, 34, 58, 34, 100, 101, 102, 97, 117, 108, 116, 34, 44, 34, 108, 97, 98, 101, 108, 95, 115, 101, 108, 101, 99, 116, 111, 114, 34, 58, 34, 97, 112, 112, 61, 110, 103, 105, 110, 120, 34, 44, 34, 102, 105, 101, 108, 100, 95, 115, 101, 108, 101, 99, 116, 111, 114, 34, 58, 34, 115, 116, 97, 116, 117, 115, 46, 112, 104, 97, 115, 101, 61, 82, 117, 110, 110, 105, 110, 103, 34, 125}

	m.
		EXPECT().
		HostCall("kubewarden", "kubernetes", "list_resources_by_namespace", expectedInputPayload).
		Return([]byte{}, nil).
		Times(1)

	host := &cap.Host{
		Client: m,
	}

	inputRequest := ListResourcesByNamespaceRequest{
		APIVersion:    "v1",
		Kind:          "Pod",
		Namespace:     "default",
		LabelSelector: "app=nginx",
		FieldSelector: "status.phase=Running",
	}

	_, err := ListResourcesByNamespace(host, inputRequest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestKubernetesListResources(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock_capabilities.NewMockWapcClient(ctrl)

	expectedInputPayload := []byte{123, 34, 97, 112, 105, 95, 118, 101, 114, 115, 105, 111, 110, 34, 58, 34, 118, 49, 34, 44, 34, 107, 105, 110, 100, 34, 58, 34, 80, 111, 100, 34, 44, 34, 108, 97, 98, 101, 108, 95, 115, 101, 108, 101, 99, 116, 111, 114, 34, 58, 34, 97, 112, 112, 61, 110, 103, 105, 110, 120, 34, 44, 34, 102, 105, 101, 108, 100, 95, 115, 101, 108, 101, 99, 116, 111, 114, 34, 58, 34, 115, 116, 97, 116, 117, 115, 46, 112, 104, 97, 115, 101, 61, 82, 117, 110, 110, 105, 110, 103, 34, 125}

	m.
		EXPECT().
		HostCall("kubewarden", "kubernetes", "list_all_resources", expectedInputPayload).
		Return([]byte{}, nil).
		Times(1)

	host := &cap.Host{
		Client: m,
	}

	inputRequest := ListAllResourcesRequest{
		APIVersion:    "v1",
		Kind:          "Pod",
		LabelSelector: "app=nginx",
		FieldSelector: "status.phase=Running",
	}

	_, err := ListResources(host, inputRequest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestKubernetesGetResource(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock_capabilities.NewMockWapcClient(ctrl)

	expectedInputPayload := []byte{123, 34, 97, 112, 105, 95, 118, 101, 114, 115, 105, 111, 110, 34, 58, 34, 118, 49, 34, 44, 34, 107, 105, 110, 100, 34, 58, 34, 80, 111, 100, 34, 44, 34, 110, 97, 109, 101, 34, 58, 34, 110, 103, 105, 110, 120, 34, 44, 34, 110, 97, 109, 101, 115, 112, 97, 99, 101, 34, 58, 34, 100, 101, 102, 97, 117, 108, 116, 34, 44, 34, 100, 105, 115, 97, 98, 108, 101, 95, 99, 97, 99, 104, 101, 34, 58, 102, 97, 108, 115, 101, 125}

	m.
		EXPECT().
		HostCall("kubewarden", "kubernetes", "get_resource", expectedInputPayload).
		Return([]byte{}, nil).
		Times(1)

	host := &cap.Host{
		Client: m,
	}

	inputRequest := GetResourceRequest{
		APIVersion:   "v1",
		Kind:         "Pod",
		Namespace:    "default",
		Name:         "nginx",
		DisableCache: false,
	}

	_, err := GetResource(host, inputRequest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
