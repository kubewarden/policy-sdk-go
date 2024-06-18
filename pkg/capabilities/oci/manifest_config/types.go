package manifest_config

import (
	specs "github.com/opencontainers/image-spec/specs-go/v1"
)

type OciImageManifestAndConfigResponse struct {
	Manifest    *specs.Manifest `json:"manifest"`
	Digest      string          `json:"digest"`
	ImageConfig *specs.Image    `json:"config"`
}
