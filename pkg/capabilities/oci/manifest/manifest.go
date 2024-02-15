package manifest

import (
	"encoding/json"
	"errors"
	"fmt"

	cap "github.com/kubewarden/policy-sdk-go/pkg/capabilities"
)

// GetOCIManifest fetches the OCI manifest for the given image URI.
// The returned value, depends of the given image. It could be a OCI image manifest
// or a OCI index image manifest. See more at:
// https://github.com/opencontainers/image-spec/blob/main/manifest.md
// https://github.com/opencontainers/image-spec/blob/main/image-index.md
// Arguments:
// * image: image to be verified (e.g.: `registry.testing.lan/busybox:1.0.0`)
func GetOCIManifest(h *cap.Host, image string) (*OciImageManifestResponse, error) {
	// build request payload, e.g: `"ghcr.io/kubewarden/policies/pod-privileged:v0.1.10"`
	payload, err := json.Marshal(image)
	if err != nil {
		return nil, fmt.Errorf("cannot serialize image URI to JSON: %w", err)
	}

	// perform host callback
	responsePayload, err := h.Client.HostCall("kubewarden", "oci", "v1/oci_manifest", payload)
	if err != nil {
		return nil, err
	}

	response := OciImageManifestResponse{}
	if err := json.Unmarshal(responsePayload, &response); err != nil {
		return nil, errors.Join(fmt.Errorf("failed to parse response from the host"), err)
	}
	return &response, nil
}
