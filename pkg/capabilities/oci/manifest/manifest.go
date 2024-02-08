package manifest

import (
	"encoding/json"
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
func GetOCIManifest(h *cap.Host, image string) (OciImageManifestResponse, error) {
	response := OciImageManifestResponse{}
	// build request payload, e.g: `"ghcr.io/kubewarden/policies/pod-privileged:v0.1.10"`
	payload, err := json.Marshal(image)
	if err != nil {
		return response, fmt.Errorf("cannot serialize image URI to JSON: %w", err)
	}

	// perform host callback
	responsePayload, err := h.Client.HostCall("kubewarden", "oci", "v1/oci_manifest", payload)
	if err != nil {
		return response, err
	}

	imageManifest := specs.Manifest{}
	indexManifest := specs.Index{}
	imageErr := json.Unmarshal(responsePayload, &imageManifest)
	indexErr := json.Unmarshal(responsePayload, &indexManifest)
	if imageErr == nil && imageManifest.MediaType == specs.MediaTypeImageManifest || imageManifest.MediaType == constants.ImageManifestMediaType {
		response.image = &imageManifest
	} else if indexErr == nil && imageManifest.MediaType == specs.MediaTypeImageIndex || indexManifest.MediaType == constants.ImageManifestListMediaType {
		response.index = &indexManifest
	} else {
		return response, fmt.Errorf("response media type not supported: %s", imageManifest.MediaType)
	}

	return response, nil
}
