package manifest_digest

import (
	"encoding/json"
	"fmt"

	cap "github.com/kubewarden/policy-sdk-go/pkg/capabilities"

	"github.com/mailru/easyjson"
)

// GetOCIManifestDigest computes the digest of the OCI object referenced by image
// Arguments:
// * image: image to be verified (e.g.: `registry.testing.lan/busybox:1.0.0`)
func GetOCIManifestDigest(h *cap.Host, image string) (string, error) {
	// build request payload, e.g: `"ghcr.io/kubewarden/policies/pod-privileged:v0.1.10"`
	payload, err := json.Marshal(image)
	if err != nil {
		return "", fmt.Errorf("cannot serialize image to JSON: %w", err)
	}

	// perform host callback
	responsePayload, err := h.Client.HostCall("kubewarden", "oci", "v1/manifest_digest", payload)
	if err != nil {
		return "", err
	}

	response := OciManifestResponse{}
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
		return "", fmt.Errorf("cannot unmarshall response: %w", err)
	}

	return response.Digest, nil
}
