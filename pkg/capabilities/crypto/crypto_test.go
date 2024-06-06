package crypto

import (
	"encoding/json"
	"testing"

	cap "github.com/kubewarden/policy-sdk-go/pkg/capabilities"

	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/mocks"
)

func TestV1IsCertificateTrusted(t *testing.T) {
	mockWapcClient := &mocks.MockWapcClient{}

	cert := Certificate{
		Encoding: Pem,
		Data:     []rune("certificate0"),
	}
	chain := []Certificate{{
		Encoding: Pem,
		Data:     []rune("certificate1"),
	}, {
		Encoding: Pem,
		Data:     []rune("certificate2"),
	}}
	not_after := "2021-10-01T00:00:00Z"

	verificationResponse := CertificateVerificationResponse{
		Trusted: true,
		Reason:  "",
	}
	verificationPayload, err := json.Marshal(verificationResponse)
	if err != nil {
		t.Fatalf("cannot serialize response object: %v", err)
	}

	expectedPayload := `{"cert":{"encoding":"Pem","data":[99,101,114,116,105,102,105,99,97,116,101,48]},"cert_chain":[{"encoding":"Pem","data":[99,101,114,116,105,102,105,99,97,116,101,49]},{"encoding":"Pem","data":[99,101,114,116,105,102,105,99,97,116,101,50]}],"not_after":"2021-10-01T00:00:00Z"}`

	mockWapcClient.
		EXPECT().
		HostCall("kubewarden", "crypto", "v1/is_certificate_trusted", []byte(expectedPayload)).
		Return(verificationPayload, nil).
		Times(1)

	host := &cap.Host{
		Client: mockWapcClient,
	}

	res, err := VerifyCert(host, cert, chain, not_after)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Trusted {
		t.Fatalf("expected trusted image, got untrusted")
	}
}
