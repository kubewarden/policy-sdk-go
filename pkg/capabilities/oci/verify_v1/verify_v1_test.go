package verify_v1

import (
	"testing"

	"encoding/json"

	"github.com/golang/mock/gomock"
	mock_capabilities "github.com/kubewarden/policy-sdk-go/mock/capabilities"
	cap "github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	oci "github.com/kubewarden/policy-sdk-go/pkg/capabilities/oci"
)

type v1VerifyTestCase struct {
	request            interface{}
	checkIsTrustedFunc func(host *cap.Host, request interface{}) (bool, error)
}

func TestV1Verify(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock_capabilities.NewMockWapcClient(ctrl)

	for description, testCase := range map[string]v1VerifyTestCase{
		"PubKeysImage": {
			request: sigstorePubKeysVerifyRequest{
				SigstorePubKeysVerify: sigstorePubKeysVerify{
					Image:       "image",
					PubKeys:     []string{"key"},
					Annotations: nil,
				},
			},
			checkIsTrustedFunc: CheckPubKeysTrustedV1,
		},
		"KeylessExactMatch": {
			request: sigstoreKeylessVerifyRequest{
				SigstoreKeylessVerify: sigstoreKeylessVerify{
					Image: "image",
					Keyless: []oci.KeylessInfo{
						{Issuer: "https://github.com/login/oauth", Subject: "mail@example.com"},
					},
					Annotations: nil,
				},
			},
			checkIsTrustedFunc: CheckKeylessTrustedV1,
		},
	} {
		t.Run(description, func(t *testing.T) {
			requestPayload, err := json.Marshal(testCase.request)
			if err != nil {
				t.Fatalf("cannot serialize request object: %v", err)
			}

			verificationResponse := oci.VerificationResponse{
				IsTrusted: true,
				Digest:    "",
			}
			verificationPayload, err := json.Marshal(verificationResponse)
			if err != nil {
				t.Fatalf("cannot serialize response object: %v", err)
			}

			m.
				EXPECT().
				HostCall("kubewarden", "oci", oci.V1.String(), requestPayload).
				Return(verificationPayload, nil).
				Times(1)

			host := &cap.Host{
				Client: m,
			}

			res, err := testCase.checkIsTrustedFunc(host, testCase.request)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !res {
				t.Fatalf("expected trusted image, got untrusted")
			}
		})
	}
}

func CheckPubKeysTrustedV1(host *cap.Host, request interface{}) (bool, error) {
	requestPubKeys := request.(sigstorePubKeysVerifyRequest)
	res, err := VerifyPubKeys(host, requestPubKeys.SigstorePubKeysVerify.Image, requestPubKeys.SigstorePubKeysVerify.PubKeys, requestPubKeys.SigstorePubKeysVerify.Annotations)
	if err != nil {
		return false, err
	}
	return res.IsTrusted, nil
}

func CheckKeylessTrustedV1(host *cap.Host, request interface{}) (bool, error) {
	requestKeyless := request.(sigstoreKeylessVerifyRequest)
	res, err := VerifyKeyless(host, requestKeyless.SigstoreKeylessVerify.Image, requestKeyless.SigstoreKeylessVerify.Keyless, requestKeyless.SigstoreKeylessVerify.Annotations)
	if err != nil {
		return false, err
	}
	return res.IsTrusted, nil
}
