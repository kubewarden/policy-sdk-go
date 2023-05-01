package crypto

import (
	"testing"

	"github.com/golang/mock/gomock"
	mock_capabilities "github.com/kubewarden/policy-sdk-go/mock/capabilities"
	cap "github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	"github.com/mailru/easyjson"
)

func TestV1IsCertificateTrusted(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock_capabilities.NewMockWapcClient(ctrl)

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
	verificationPayload, err := easyjson.Marshal(verificationResponse)
	if err != nil {
		t.Fatalf("cannot serialize response object: %v", err)
	}

	expectedPayload := []byte{123, 34, 99, 101, 114, 116, 34, 58, 123, 34, 101, 110, 99, 111, 100, 105, 110, 103, 34, 58, 34, 80, 101, 109, 34, 44, 34, 100, 97, 116, 97, 34, 58, 91, 57, 57, 44, 49, 48, 49, 44, 49, 49, 52, 44, 49, 49, 54, 44, 49, 48, 53, 44, 49, 48, 50, 44, 49, 48, 53, 44, 57, 57, 44, 57, 55, 44, 49, 49, 54, 44, 49, 48, 49, 44, 52, 56, 93, 125, 44, 34, 99, 101, 114, 116, 95, 99, 104, 97, 105, 110, 34, 58, 91, 123, 34, 101, 110, 99, 111, 100, 105, 110, 103, 34, 58, 34, 80, 101, 109, 34, 44, 34, 100, 97, 116, 97, 34, 58, 91, 57, 57, 44, 49, 48, 49, 44, 49, 49, 52, 44, 49, 49, 54, 44, 49, 48, 53, 44, 49, 48, 50, 44, 49, 48, 53, 44, 57, 57, 44, 57, 55, 44, 49, 49, 54, 44, 49, 48, 49, 44, 52, 57, 93, 125, 44, 123, 34, 101, 110, 99, 111, 100, 105, 110, 103, 34, 58, 34, 80, 101, 109, 34, 44, 34, 100, 97, 116, 97, 34, 58, 91, 57, 57, 44, 49, 48, 49, 44, 49, 49, 52, 44, 49, 49, 54, 44, 49, 48, 53, 44, 49, 48, 50, 44, 49, 48, 53, 44, 57, 57, 44, 57, 55, 44, 49, 49, 54, 44, 49, 48, 49, 44, 53, 48, 93, 125, 93, 44, 34, 110, 111, 116, 95, 97, 102, 116, 101, 114, 34, 58, 34, 50, 48, 50, 49, 45, 49, 48, 45, 48, 49, 84, 48, 48, 58, 48, 48, 58, 48, 48, 90, 34, 125}

	m.
		EXPECT().
		HostCall("kubewarden", "crypto", "v1/is_certificate_trusted", expectedPayload).
		Return(verificationPayload, nil).
		Times(1)

	host := &cap.Host{
		Client: m,
	}

	res, err := VerifyCert(host, cert, chain, not_after)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res {
		t.Fatalf("expected trusted image, got untrusted")
	}
}
