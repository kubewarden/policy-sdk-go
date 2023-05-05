package manifest_digest

import (
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	mock_capabilities "github.com/kubewarden/policy-sdk-go/mock/capabilities"
	cap "github.com/kubewarden/policy-sdk-go/pkg/capabilities"
)

func TestV1ManifestDigest(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock_capabilities.NewMockWapcClient(ctrl)

	digestResponse := OciManifestResponse{
		Digest: "myhash",
	}
	digestPayload, err := json.Marshal(digestResponse)
	if err != nil {
		t.Fatalf("cannot serialize response object: %v", err)
	}

	expectedPayload := `"myimage:latest"`

	m.
		EXPECT().
		HostCall("kubewarden", "oci", "v1/manifest_digest", []byte(expectedPayload)).
		Return(digestPayload, nil).
		Times(1)

	host := &cap.Host{
		Client: m,
	}

	res, err := GetOCIManifestDigest(host, "myimage:latest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != digestResponse.Digest {
		t.Fatalf("unexpected error")
	}
}
