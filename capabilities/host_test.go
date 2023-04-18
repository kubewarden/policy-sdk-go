package capabilities

import (
	"testing"

	"github.com/golang/mock/gomock"
	mock_capabilities "github.com/kubewarden/policy-sdk-go/mock"
	"github.com/mailru/easyjson"
)

type v2VerifyTestCase struct {
	request            easyjson.Marshaler
	expectedPayload    []byte
	checkIsTrustedFunc func(host Host, request easyjson.Marshaler) (bool, error)
}

func TestV2Verify(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock_capabilities.NewMockWapcClient(ctrl)

	for description, testCase := range map[string]v2VerifyTestCase{
		"PubKeysImage": {
			request: sigstorePubKeysVerifyV2{
				Image:       "myimage:latest",
				PubKeys:     []string{"pubkey1", "pubkey2"},
				Annotations: nil,
			},
			expectedPayload:    []byte{123, 34, 116, 121, 112, 101, 34, 58, 34, 83, 105, 103, 115, 116, 111, 114, 101, 80, 117, 98, 75, 101, 121, 86, 101, 114, 105, 102, 121, 34, 44, 34, 105, 109, 97, 103, 101, 34, 58, 34, 109, 121, 105, 109, 97, 103, 101, 58, 108, 97, 116, 101, 115, 116, 34, 44, 34, 112, 117, 98, 95, 107, 101, 121, 115, 34, 58, 91, 34, 112, 117, 98, 107, 101, 121, 49, 34, 44, 34, 112, 117, 98, 107, 101, 121, 50, 34, 93, 44, 34, 97, 110, 110, 111, 116, 97, 116, 105, 111, 110, 115, 34, 58, 110, 117, 108, 108, 125},
			checkIsTrustedFunc: CheckPubKeysImageTrusted,
		},
		"KeylessExactMatch": {
			request: sigstoreKeylessVerifyExactV2{
				Image: "myimage:latest",
				Keyless: []KeylessInfo{
					{Issuer: "https://github.com/login/oauth", Subject: "mail@example.com"},
				},
				Annotations: nil,
			},
			expectedPayload:    []byte{123, 34, 116, 121, 112, 101, 34, 58, 34, 83, 105, 103, 115, 116, 111, 114, 101, 75, 101, 121, 108, 101, 115, 115, 86, 101, 114, 105, 102, 121, 34, 44, 34, 105, 109, 97, 103, 101, 34, 58, 34, 109, 121, 105, 109, 97, 103, 101, 58, 108, 97, 116, 101, 115, 116, 34, 44, 34, 107, 101, 121, 108, 101, 115, 115, 34, 58, 91, 123, 34, 105, 115, 115, 117, 101, 114, 34, 58, 34, 104, 116, 116, 112, 115, 58, 47, 47, 103, 105, 116, 104, 117, 98, 46, 99, 111, 109, 47, 108, 111, 103, 105, 110, 47, 111, 97, 117, 116, 104, 34, 44, 34, 115, 117, 98, 106, 101, 99, 116, 34, 58, 34, 109, 97, 105, 108, 64, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 34, 125, 93, 44, 34, 97, 110, 110, 111, 116, 97, 116, 105, 111, 110, 115, 34, 58, 110, 117, 108, 108, 125},
			checkIsTrustedFunc: CheckKeylessExactMatchTrusted,
		},
		"KeylessPrefixMatch": {
			request: sigstoreKeylessPrefixVerifyV2{
				Image: "myimage:latest",
				KeylessPrefix: []KeylessPrefixInfo{
					{Issuer: "https://github.com/login/oauth", UrlPrefix: "https://example.com"},
				},
				Annotations: nil,
			},
			expectedPayload:    []byte{123, 34, 116, 121, 112, 101, 34, 58, 34, 83, 105, 103, 115, 116, 111, 114, 101, 75, 101, 121, 108, 101, 115, 115, 80, 114, 101, 102, 105, 120, 86, 101, 114, 105, 102, 121, 34, 44, 34, 105, 109, 97, 103, 101, 34, 58, 34, 109, 121, 105, 109, 97, 103, 101, 58, 108, 97, 116, 101, 115, 116, 34, 44, 34, 107, 101, 121, 108, 101, 115, 115, 95, 112, 114, 101, 102, 105, 120, 34, 58, 91, 123, 34, 105, 115, 115, 117, 101, 114, 34, 58, 34, 104, 116, 116, 112, 115, 58, 47, 47, 103, 105, 116, 104, 117, 98, 46, 99, 111, 109, 47, 108, 111, 103, 105, 110, 47, 111, 97, 117, 116, 104, 34, 44, 34, 117, 114, 108, 95, 112, 114, 101, 102, 105, 120, 34, 58, 34, 104, 116, 116, 112, 115, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 34, 125, 93, 44, 34, 97, 110, 110, 111, 116, 97, 116, 105, 111, 110, 115, 34, 58, 110, 117, 108, 108, 125},
			checkIsTrustedFunc: CheckKeylessPrefixMatchTrusted,
		},
		"KeylessGithubActions": {
			request: sigstoreGithubActionsVerifyV2{
				Image:       "myimage:latest",
				Owner:       "myorg",
				Repo:        "myrepo",
				Annotations: nil,
			},
			expectedPayload:    []byte{123, 34, 116, 121, 112, 101, 34, 58, 34, 83, 105, 103, 115, 116, 111, 114, 101, 71, 105, 116, 104, 117, 98, 65, 99, 116, 105, 111, 110, 115, 86, 101, 114, 105, 102, 121, 34, 44, 34, 105, 109, 97, 103, 101, 34, 58, 34, 109, 121, 105, 109, 97, 103, 101, 58, 108, 97, 116, 101, 115, 116, 34, 44, 34, 111, 119, 110, 101, 114, 34, 58, 34, 109, 121, 111, 114, 103, 34, 44, 34, 114, 101, 112, 111, 34, 58, 34, 109, 121, 114, 101, 112, 111, 34, 44, 34, 97, 110, 110, 111, 116, 97, 116, 105, 111, 110, 115, 34, 58, 110, 117, 108, 108, 125},
			checkIsTrustedFunc: CheckKeylessGithubActionsTrusted,
		},
		"Certificate": {
			request: sigstoreCertificateVerifyV2{
				Image:              "myimage:latest",
				Certificate:        []rune("certificate0"),
				CertificateChain:   [][]rune{[]rune("certificate1"), []rune("certificate2")},
				RequireRekorBundle: false,
				Annotations:        nil,
			},
			expectedPayload:    []byte{123, 34, 116, 121, 112, 101, 34, 58, 34, 83, 105, 103, 115, 116, 111, 114, 101, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 86, 101, 114, 105, 102, 121, 34, 44, 34, 105, 109, 97, 103, 101, 34, 58, 34, 109, 121, 105, 109, 97, 103, 101, 58, 108, 97, 116, 101, 115, 116, 34, 44, 34, 99, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 34, 58, 91, 57, 57, 44, 49, 48, 49, 44, 49, 49, 52, 44, 49, 49, 54, 44, 49, 48, 53, 44, 49, 48, 50, 44, 49, 48, 53, 44, 57, 57, 44, 57, 55, 44, 49, 49, 54, 44, 49, 48, 49, 44, 52, 56, 93, 44, 34, 99, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 95, 99, 104, 97, 105, 110, 34, 58, 91, 91, 57, 57, 44, 49, 48, 49, 44, 49, 49, 52, 44, 49, 49, 54, 44, 49, 48, 53, 44, 49, 48, 50, 44, 49, 48, 53, 44, 57, 57, 44, 57, 55, 44, 49, 49, 54, 44, 49, 48, 49, 44, 52, 57, 93, 44, 91, 57, 57, 44, 49, 48, 49, 44, 49, 49, 52, 44, 49, 49, 54, 44, 49, 48, 53, 44, 49, 48, 50, 44, 49, 48, 53, 44, 57, 57, 44, 57, 55, 44, 49, 49, 54, 44, 49, 48, 49, 44, 53, 48, 93, 93, 44, 34, 114, 101, 113, 117, 105, 114, 101, 95, 114, 101, 107, 111, 114, 95, 98, 117, 110, 100, 108, 101, 34, 58, 102, 97, 108, 115, 101, 44, 34, 97, 110, 110, 111, 116, 97, 116, 105, 111, 110, 115, 34, 58, 110, 117, 108, 108, 125},
			checkIsTrustedFunc: CheckCertificateTrusted,
		},
	} {
		t.Run(description, func(t *testing.T) {
			verificationResponse := VerificationResponse{
				IsTrusted: true,
				Digest:    "",
			}
			verificationPayload, err := easyjson.Marshal(verificationResponse)
			if err != nil {
				t.Fatalf("cannot serialize response object: %v", err)
			}

			m.
				EXPECT().
				HostCall("kubewarden", "oci", V2.String(), testCase.expectedPayload).
				Return(verificationPayload, nil).
				Times(1)

			host := Host{
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

func CheckPubKeysImageTrusted(host Host, request easyjson.Marshaler) (bool, error) {
	requestPubKeys := request.(sigstorePubKeysVerifyV2)
	res, err := host.VerifyPubKeysImageV2(requestPubKeys.Image, requestPubKeys.PubKeys, requestPubKeys.Annotations)
	if err != nil {
		return false, err
	}
	return res.IsTrusted, nil
}

func CheckKeylessExactMatchTrusted(host Host, request easyjson.Marshaler) (bool, error) {
	requestKeylessExactMatch := request.(sigstoreKeylessVerifyExactV2)
	res, err := host.VerifyKeylessExactMatchV2(requestKeylessExactMatch.Image, requestKeylessExactMatch.Keyless, requestKeylessExactMatch.Annotations)
	if err != nil {
		return false, err
	}
	return res.IsTrusted, nil
}

func CheckKeylessPrefixMatchTrusted(host Host, request easyjson.Marshaler) (bool, error) {
	requestKeylessPrefixMatch := request.(sigstoreKeylessPrefixVerifyV2)
	res, err := host.VerifyKeylessPrefixMatchV2(requestKeylessPrefixMatch.Image, requestKeylessPrefixMatch.KeylessPrefix, requestKeylessPrefixMatch.Annotations)
	if err != nil {
		return false, err
	}
	return res.IsTrusted, nil
}

func CheckKeylessGithubActionsTrusted(host Host, request easyjson.Marshaler) (bool, error) {
	requestKeylessGithubActions := request.(sigstoreGithubActionsVerifyV2)
	res, err := host.VerifyKeylessGithubActionsV2(requestKeylessGithubActions.Image, requestKeylessGithubActions.Owner, requestKeylessGithubActions.Repo, requestKeylessGithubActions.Annotations)
	if err != nil {
		return false, err
	}
	return res.IsTrusted, nil
}

func CheckCertificateTrusted(host Host, request easyjson.Marshaler) (bool, error) {
	requestCertificate := request.(sigstoreCertificateVerifyV2)

	chain := make([]string, len(requestCertificate.CertificateChain))
	for i, c := range requestCertificate.CertificateChain {
		chain[i] = string(c)
	}

	res, err := host.VerifyCertificateV2(requestCertificate.Image, string(requestCertificate.Certificate), chain, requestCertificate.RequireRekorBundle, requestCertificate.Annotations)
	if err != nil {
		return false, err
	}
	return res.IsTrusted, nil
}

type v1VerifyTestCase struct {
	request            easyjson.Marshaler
	checkIsTrustedFunc func(host Host, request easyjson.Marshaler) (bool, error)
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
					Keyless: []KeylessInfo{
						{Issuer: "https://github.com/login/oauth", Subject: "mail@example.com"},
					},
					Annotations: nil,
				},
			},
			checkIsTrustedFunc: CheckKeylessTrustedV1,
		},
	} {
		t.Run(description, func(t *testing.T) {
			requestPayload, err := easyjson.Marshal(testCase.request)
			if err != nil {
				t.Fatalf("cannot serialize request object: %v", err)
			}

			verificationResponse := VerificationResponse{
				IsTrusted: true,
				Digest:    "",
			}
			verificationPayload, err := easyjson.Marshal(verificationResponse)
			if err != nil {
				t.Fatalf("cannot serialize response object: %v", err)
			}

			m.
				EXPECT().
				HostCall("kubewarden", "oci", V1.String(), requestPayload).
				Return(verificationPayload, nil).
				Times(1)

			host := Host{
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

func CheckPubKeysTrustedV1(host Host, request easyjson.Marshaler) (bool, error) {
	requestPubKeys := request.(sigstorePubKeysVerifyRequest)
	res, err := host.VerifyPubKeys(requestPubKeys.SigstorePubKeysVerify.Image, requestPubKeys.SigstorePubKeysVerify.PubKeys, requestPubKeys.SigstorePubKeysVerify.Annotations)
	if err != nil {
		return false, err
	}
	return res.IsTrusted, nil
}

func CheckKeylessTrustedV1(host Host, request easyjson.Marshaler) (bool, error) {
	requestKeyless := request.(sigstoreKeylessVerifyRequest)
	res, err := host.VerifyKeyless(requestKeyless.SigstoreKeylessVerify.Image, requestKeyless.SigstoreKeylessVerify.Keyless, requestKeyless.SigstoreKeylessVerify.Annotations)
	if err != nil {
		return false, err
	}
	return res.IsTrusted, nil
}
