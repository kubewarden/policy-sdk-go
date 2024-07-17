package manifest

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kubewarden/policy-sdk-go/constants"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
)

type OciImageManifestResponse struct {
	Image *specs.Manifest `json:"image"`
	Index *specs.Index    `json:"index"`
}

func (r OciImageManifestResponse) ImageManifest() *specs.Manifest {
	return r.Image
}

func (r OciImageManifestResponse) IndexManifest() *specs.Index {
	return r.Index
}

func (r *OciImageManifestResponse) UnmarshalJSON(b []byte) error {
	imageManifest := specs.Manifest{}
	if err := json.Unmarshal(b, &imageManifest); err == nil {
		if isImageMediaType(imageManifest.MediaType) {
			r.Image = &imageManifest
			return nil
		}
	}
	indexManifest := specs.Index{}
	if err := json.Unmarshal(b, &indexManifest); err == nil {
		if isImageIndexMediaType(indexManifest.MediaType) {
			r.Index = &indexManifest
			return nil
		}
		return fmt.Errorf("not a valid media type: %s", indexManifest.MediaType)
	}
	return errors.New("cannot decode response")
}

func isImageIndexMediaType(mediaType string) bool {
	return mediaType == specs.MediaTypeImageIndex || mediaType == constants.ImageManifestListMediaType
}

func isImageMediaType(mediaType string) bool {
	return mediaType == specs.MediaTypeImageManifest || mediaType == constants.ImageManifestMediaType
}
