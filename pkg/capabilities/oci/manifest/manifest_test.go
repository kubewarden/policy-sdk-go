package manifest

import (
	_ "crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/kubewarden/policy-sdk-go/constants"
	mock_capabilities "github.com/kubewarden/policy-sdk-go/mock/capabilities"
	cap "github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
)

func buildHostMock(t *testing.T, expectedPayload []byte, returnPayload []byte) *cap.Host {
	ctrl := gomock.NewController(t)
	m := mock_capabilities.NewMockWapcClient(ctrl)
	m.EXPECT().HostCall("kubewarden", "oci", "v1/oci_manifest", expectedPayload).Return(returnPayload, nil).Times(1)
	return &cap.Host{
		Client: m,
	}
}

func buildManifest(mediaType string) interface{} {
	return specs.Manifest{
		MediaType: mediaType,
		Config: specs.Descriptor{
			MediaType:   mediaType,
			Digest:      digest.FromString("mydummydigest"),
			Size:        1024,
			URLs:        []string{"ghcr.io/kubewarden/policy-server:latest"},
			Annotations: map[string]string{"annotation": "value"},
			Platform: &specs.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
		},
		Layers:      []specs.Descriptor{},
		Annotations: map[string]string{"annotation": "value"},
	}
}

func buildIndexManifest(mediaType string) interface{} {
	return specs.Index{
		MediaType: mediaType,
		Manifests: []specs.Descriptor{{
			MediaType:   specs.MediaTypeDescriptor,
			Digest:      digest.FromString("mydummydigest"),
			Size:        1024,
			URLs:        []string{"ghcr.io/kubewarden/policy-server:latest"},
			Annotations: map[string]string{"annotation": "value"},
			Platform: &specs.Platform{
				Architecture: "amd64",
				OS:           "linux",
			},
		},
		},
		// Annotations contains arbitrary metadata for the image index.
		Annotations: map[string]string{"annonation": "annotationValue"},
	}
}

func TestV1OciManifest(t *testing.T) {

	tests := []struct {
		manifest                     interface{}
		failsBecauseUnknownMediaType bool
	}{
		{
			manifest:                     buildManifest(specs.MediaTypeImageManifest),
			failsBecauseUnknownMediaType: false,
		},
		{
			manifest:                     buildManifest(constants.ImageManifestMediaType),
			failsBecauseUnknownMediaType: false,
		},
		{
			manifest:                     buildIndexManifest(specs.MediaTypeImageIndex),
			failsBecauseUnknownMediaType: false,
		},
		{
			manifest:                     buildIndexManifest(constants.ImageManifestListMediaType),
			failsBecauseUnknownMediaType: false,
		},
		{
			manifest:                     buildIndexManifest(specs.MediaTypeDescriptor),
			failsBecauseUnknownMediaType: true,
		},
		{
			manifest:                     buildIndexManifest(specs.MediaTypeImageConfig),
			failsBecauseUnknownMediaType: true,
		},
		{
			manifest:                     buildIndexManifest(specs.MediaTypeImageLayerGzip),
			failsBecauseUnknownMediaType: true,
		},
		{
			manifest:                     buildManifest(specs.MediaTypeDescriptor),
			failsBecauseUnknownMediaType: true,
		},
		{
			manifest:                     buildManifest(specs.MediaTypeImageConfig),
			failsBecauseUnknownMediaType: true,
		},
		{
			manifest:                     buildManifest(specs.MediaTypeImageLayerGzip),
			failsBecauseUnknownMediaType: true,
		},
	}
	for _, test := range tests {
		t.Run("", func(t *testing.T) {
			manifestPayload, err := json.Marshal(test.manifest)
			if err != nil {
				t.Fatalf("cannot serialize response object: %v", err)
			}
			expectedPayload := `"myimage:latest"`
			host := buildHostMock(t, []byte(expectedPayload), manifestPayload)

			res, err := GetOCIManifest(host, "myimage:latest")

			if test.failsBecauseUnknownMediaType {
				if err == nil || !strings.Contains(err.Error(), "not a valid media type") {
					t.Fatal("expected an invalid media type error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var manifest interface{}
			switch test.manifest.(type) {
			case specs.Manifest:
				manifest = *res.ImageManifest()
			case specs.Index:
				manifest = *res.IndexManifest()
			default:
				t.Fatal("unexpected manifest")
			}
			if diff := cmp.Diff(manifest, test.manifest); diff != "" {
				t.Fatalf("unexpected manifest:\n%s", diff)
			}
		})
	}
}
