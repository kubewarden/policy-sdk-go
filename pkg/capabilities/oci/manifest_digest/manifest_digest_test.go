package manifest_digest

import (
	"encoding/json"
	"testing"

	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"

	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/mocks"
)

func TestV1ManifestDigest(t *testing.T) {
	mockWapcClient := &mocks.MockWapcClient{}

	digestResponse := OciManifestResponse{
		Digest: "myhash",
	}
	digestPayload, err := json.Marshal(digestResponse)
	if err != nil {
		t.Fatalf("cannot serialize response object: %v", err)
	}

	expectedPayload := `"myimage:latest"`

	mockWapcClient.
		EXPECT().
		HostCall("kubewarden", "oci", "v1/manifest_digest", []byte(expectedPayload)).
		Return(digestPayload, nil).
		Times(1)

	host := &capabilities.Host{
		Client: mockWapcClient,
	}

	res, err := GetOCIManifestDigest(host, "myimage:latest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != digestResponse.Digest {
		t.Fatalf("unexpected error")
	}
}
