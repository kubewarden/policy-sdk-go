package manifest

import (
	_ "crypto/sha256"
	"encoding/json"
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

func TestV1OciImageManifest(t *testing.T) {
	tests := []string{specs.MediaTypeImageManifest, constants.ImageManifestMediaType}
	for _, mediaType := range tests {
		t.Run(mediaType, func(t *testing.T) {
			imageManifest := specs.Manifest{
				MediaType: mediaType,
				Config: specs.Descriptor{
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
				Layers:      []specs.Descriptor{},
				Annotations: map[string]string{"annotation": "value"},
			}
			manifestPayload, err := json.Marshal(imageManifest)
			if err != nil {
				t.Fatalf("cannot serialize response object: %v", err)
			}
			expectedPayload := `"myimage:latest"`
			host := buildHostMock(t, []byte(expectedPayload), manifestPayload)

			res, err := GetOCIManifest(host, "myimage:latest")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if res.IndexManifest() != nil {
				t.Fatal("response should not be an index manifest")
			}
			if diff := cmp.Diff(*res.ImageManifest(), imageManifest); diff != "" {
				t.Fatalf("unexpected image manifest:\n%s", diff)
			}
		})
	}
}

func TestV1OciIndexManifest(t *testing.T) {
	tests := []string{specs.MediaTypeImageIndex, constants.ImageManifestListMediaType}
	for _, mediaType := range tests {
		t.Run(mediaType, func(t *testing.T) {
			indexManifest := specs.Index{
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
			manifestPayload, err := json.Marshal(indexManifest)
			if err != nil {
				t.Fatalf("cannot serialize response object: %v", err)
			}
			expectedPayload := `"myimage:latest"`
			host := buildHostMock(t, []byte(expectedPayload), manifestPayload)

			res, err := GetOCIManifest(host, "myimage:latest")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.ImageManifest() != nil {
				t.Fatalf("response should not be an image manifest:\n%v", res.ImageManifest())
			}
			if diff := cmp.Diff(*res.IndexManifest(), indexManifest); diff != "" {
				t.Fatalf("unexpected index manifest:\n%s", diff)
			}
		})
	}
}

func TestV1OciManifestInvalidMediaTypes(t *testing.T) {
	tests := []string{specs.MediaTypeDescriptor, specs.MediaTypeImageConfig, specs.MediaTypeImageLayerGzip}
	for _, mediaType := range tests {
		t.Run(mediaType, func(t *testing.T) {
			indexManifest := specs.Index{
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
			manifestPayload, err := json.Marshal(indexManifest)
			if err != nil {
				t.Fatalf("cannot serialize response object: %v", err)
			}
			expectedPayload := `"myimage:latest"`
			host := buildHostMock(t, []byte(expectedPayload), manifestPayload)

			_, err = GetOCIManifest(host, "myimage:latest")
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
