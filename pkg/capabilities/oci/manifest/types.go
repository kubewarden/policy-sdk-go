package manifest

import (
	"encoding/json"
	"fmt"
	"github.com/kubewarden/policy-sdk-go/constants"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
)

type OciImageManifestResponse struct {
	image *specs.Manifest
	index *specs.Index
}

func (r OciImageManifestResponse) ImageManifest() *specs.Manifest {
	return r.image
}

func (r OciImageManifestResponse) IndexManifest() *specs.Index {
	return r.index
}

func (r *OciImageManifestResponse) UnmarshalJSON(b []byte) error {
	imageManifest := specs.Manifest{}
	if err := json.Unmarshal(b, &imageManifest); err == nil {
		if isImageMediaType(imageManifest.MediaType) {
			r.image = &imageManifest
			return nil
		}
	}
	indexManifest := specs.Index{}
	if err := json.Unmarshal(b, &indexManifest); err == nil {
		if isImageIndexMediaType(indexManifest.MediaType) {
			r.index = &indexManifest
			return nil
		}
		return fmt.Errorf("not a valid media type: %s", indexManifest.MediaType)
	}
	return fmt.Errorf("cannot decode response")
}

func isImageIndexMediaType(mediaType string) bool {
	return mediaType == specs.MediaTypeImageIndex || mediaType == constants.ImageManifestListMediaType
}

func isImageMediaType(mediaType string) bool {
	return mediaType == specs.MediaTypeImageManifest || mediaType == constants.ImageManifestMediaType
}
