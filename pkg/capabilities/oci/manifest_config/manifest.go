package manifest_config

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"
)

// GetOCIManifestAndConfig fetches the OCI manifest and configuration for the given image URI.
// Arguments:
// * image: image to be verified (e.g.: `registry.testing.lan/busybox:1.0.0`).
func GetOCIManifestAndConfig(h *capabilities.Host, image string) (*OciImageManifestAndConfigResponse, error) {
	// build request payload, e.g: `"ghcr.io/kubewarden/policies/pod-privileged:v0.1.10"`
	payload, err := json.Marshal(image)
	if err != nil {
		return nil, fmt.Errorf("cannot serialize image URI to JSON: %w", err)
	}

	// perform host callback
	responsePayload, err := h.Client.HostCall("kubewarden", "oci", "v1/oci_manifest_config", payload)
	if err != nil {
		return nil, err
	}

	response := OciImageManifestAndConfigResponse{}
	if err = json.Unmarshal(responsePayload, &response); err != nil {
		return nil, errors.Join(errors.New("failed to parse response from the host"), err)
	}
	return &response, nil
}
