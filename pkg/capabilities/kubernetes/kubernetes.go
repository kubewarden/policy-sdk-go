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

// CanI checks if the user has permissions to perform an action on resources.
func CanI(h *capabilities.Host, req SubjectAccessReviewRequest) (SubjectAccessReviewStatus, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return SubjectAccessReviewStatus{}, fmt.Errorf("cannot serialize request object: %w", err)
	}

	// perform callback
	responsePayload, err := h.Client.HostCall("kubewarden", "kubernetes", "can_i", payload)
	if err != nil {
		return SubjectAccessReviewStatus{}, err
	}

	responseObj := SubjectAccessReviewStatus{}
	if err = json.Unmarshal(responsePayload, &responseObj); err != nil {
		return SubjectAccessReviewStatus{}, fmt.Errorf("cannot unmarshall response object: %w", err)
	}

	return responseObj, nil
}
