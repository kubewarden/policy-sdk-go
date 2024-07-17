package manifest_config

import (
	_ "crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/google/go-cmp/cmp"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/mocks"
)

func buildHostMock(imageURI string, returnPayload []byte) (*capabilities.Host, error) {
	mockWapcClient := &mocks.MockWapcClient{}
	expectedPayload, err := json.Marshal(imageURI)
	if err != nil {
		return nil, err
	}
	mockWapcClient.EXPECT().HostCall("kubewarden", "oci", "v1/oci_manifest_config", expectedPayload).Return(returnPayload, nil).Times(1)
	return &capabilities.Host{
		Client: mockWapcClient,
	}, nil
}

func buildManifestAndConfigResponse() interface{} {
	manifest := specs.Manifest{
		MediaType: specs.MediaTypeImageManifest,
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
	now := time.Now()
	image := specs.Image{
		Created: &now,
		Author:  "kubewarden",
		Platform: specs.Platform{
			Architecture: "amd64",
			OS:           "linux",
			OSVersion:    "1.0.0",
			OSFeatures:   []string{"feature1", "feature2"},
			Variant:      "variant",
		},
		Config: specs.ImageConfig{
			User:         "1000",
			Cmd:          []string{"echo", "hello"},
			Entrypoint:   []string{"echo"},
			Env:          []string{"key=value"},
			WorkingDir:   "/",
			Labels:       map[string]string{"label": "value"},
			StopSignal:   "SIGTERM",
			ExposedPorts: map[string]struct{}{"80/tcp": {}},
			Volumes:      map[string]struct{}{"/tmp": {}},
			ArgsEscaped:  true,
		},
		RootFS: specs.RootFS{
			Type:    "layers",
			DiffIDs: []digest.Digest{digest.FromString("mydummydigest")},
		},
		History: []specs.History{
			{
				Created:    &now,
				CreatedBy:  "kubewarden",
				Author:     "kubewarden",
				Comment:    "initial commit",
				EmptyLayer: false,
			},
		},
	}
	return OciImageManifestAndConfigResponse{
		Manifest:    &manifest,
		Digest:      "mydummydigest",
		ImageConfig: &image,
	}
}

func TestOciManifestAndConfig(t *testing.T) {
	manifest := buildManifestAndConfigResponse()
	manifestPayload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("cannot serialize response object: %v", err)
	}
	response := OciImageManifestAndConfigResponse{}
	if err = json.Unmarshal(manifestPayload, &response); err != nil {
		t.Fatalf("failed to parse response from the host")
	}

	imageURI := "myimage:latest"
	host, err := buildHostMock(imageURI, manifestPayload)
	if err != nil {
		t.Fatalf("cannot build host mock: %q", err)
	}

	res, err := GetOCIManifestAndConfig(host, imageURI)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff := cmp.Diff(*res, manifest); diff != "" {
		t.Fatalf("invalid manifest and config response:\n%s", diff)
	}
}
