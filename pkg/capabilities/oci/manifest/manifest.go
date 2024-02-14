package manifest

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kubewarden/policy-sdk-go/constants"
	cap "github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
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

	imageManifest := specs.Manifest{}
	if err := json.Unmarshal(responsePayload, &imageManifest); err == nil {
		if imageManifest.MediaType == specs.MediaTypeImageManifest || imageManifest.MediaType == constants.ImageManifestMediaType {
			response := OciImageManifestResponse{
				image: &imageManifest,
			}
			return &response, nil
		} else {
			indexManifest := specs.Index{}
			if err := json.Unmarshal(responsePayload, &indexManifest); err == nil {
				if indexManifest.MediaType == specs.MediaTypeImageIndex || indexManifest.MediaType == constants.ImageManifestListMediaType {
					response := OciImageManifestResponse{
						index: &indexManifest,
					}
					return &response, nil
				}
				return nil, fmt.Errorf("not a valid media type: %s", indexManifest.MediaType)
			}
		}
	}
	return nil, errors.New("cannot decode response")
}
