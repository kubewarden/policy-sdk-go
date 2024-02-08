package manifest

import specs "github.com/opencontainers/image-spec/specs-go/v1"

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
