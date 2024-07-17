package kubernetes

import (
	"encoding/json"
	"fmt"

	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"
)

// ListResourcesByNamespace gets all the Kubernetes resources defined inside of
// the given namespace
// Note: cannot be used for cluster-wide resources.
func ListResourcesByNamespace(h *capabilities.Host, req ListResourcesByNamespaceRequest) ([]byte, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return []byte{}, fmt.Errorf("cannot serialize request object: %w", err)
	}

	// perform callback
	responsePayload, err := h.Client.HostCall("kubewarden", "kubernetes", "list_resources_by_namespace", payload)
	if err != nil {
		return []byte{}, err
	}

	return responsePayload, nil
}

// ListResources gets all the Kubernetes resources defined inside of the cluster.
// Note: this has be used for cluster-wide resources.
func ListResources(h *capabilities.Host, req ListAllResourcesRequest) ([]byte, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return []byte{}, fmt.Errorf("cannot serialize request object: %w", err)
	}

	// perform callback
	responsePayload, err := h.Client.HostCall("kubewarden", "kubernetes", "list_resources_all", payload)
	if err != nil {
		return []byte{}, err
	}

	return responsePayload, nil
}

// GetResource gets a specific Kubernetes resource.
func GetResource(h *capabilities.Host, req GetResourceRequest) ([]byte, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return []byte{}, fmt.Errorf("cannot serialize request object: %w", err)
	}

	// perform callback
	responsePayload, err := h.Client.HostCall("kubewarden", "kubernetes", "get_resource", payload)
	if err != nil {
		return []byte{}, err
	}

	return responsePayload, nil
}
