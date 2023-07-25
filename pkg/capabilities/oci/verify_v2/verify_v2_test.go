package verify_v2

import (
	"testing"

	"encoding/json"

	"github.com/golang/mock/gomock"
	mock_capabilities "github.com/kubewarden/policy-sdk-go/mock/capabilities"
	cap "github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	oci "github.com/kubewarden/policy-sdk-go/pkg/capabilities/oci"
)

type v2VerifyTestCase struct {
	request            interface{}
	expectedPayload    string
	checkIsTrustedFunc func(host *cap.Host, request interface{}) (bool, error)
}

func TestV2Verify(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock_capabilities.NewMockWapcClient(ctrl)

	for description, testCase := range map[string]v2VerifyTestCase{
		"PubKeysImage": {
			request: sigstorePubKeysVerify{
				Image:       "myimage:latest",
				PubKeys:     []string{"pubkey1", "pubkey2"},
				Annotations: nil,
			},
			expectedPayload:    `{"type":"SigstorePubKeyVerify","image":"myimage:latest","pub_keys":["pubkey1","pubkey2"],"annotations":null}`,
			checkIsTrustedFunc: CheckPubKeysImageTrusted,
		},
		"KeylessExactMatch": {
			request: sigstoreKeylessVerifyExact{
				Image: "myimage:latest",
				Keyless: []oci.KeylessInfo{
					{Issuer: "https://github.com/login/oauth", Subject: "mail@example.com"},
				},
				Annotations: nil,
			},
			expectedPayload:    `{"type":"SigstoreKeylessVerify","image":"myimage:latest","keyless":[{"issuer":"https://github.com/login/oauth","subject":"mail@example.com"}],"annotations":null}`,
			checkIsTrustedFunc: CheckKeylessExactMatchTrusted,
		},
		"KeylessPrefixMatch": {
			request: sigstoreKeylessPrefixVerify{
				Image: "myimage:latest",
				KeylessPrefix: []KeylessPrefixInfo{
					{Issuer: "https://github.com/login/oauth", UrlPrefix: "https://example.com"},
				},
				Annotations: nil,
			},
			expectedPayload:    `{"type":"SigstoreKeylessPrefixVerify","image":"myimage:latest","keyless_prefix":[{"issuer":"https://github.com/login/oauth","url_prefix":"https://example.com"}],"annotations":null}`,
			checkIsTrustedFunc: CheckKeylessPrefixMatchTrusted,
		},
		"KeylessGithubActions": {
			request: sigstoreGithubActionsVerify{
				Image:       "myimage:latest",
				Owner:       "myorg",
				Repo:        "myrepo",
				Annotations: nil,
			},
			expectedPayload:    `{"type":"SigstoreGithubActionsVerify","image":"myimage:latest","owner":"myorg","repo":"myrepo","annotations":null}`,
			checkIsTrustedFunc: CheckKeylessGithubActionsTrusted,
		},
		"Certificate": {
			request: sigstoreCertificateVerify{
				Image:              "myimage:latest",
				Certificate:        []rune("certificate0"),
				CertificateChain:   [][]rune{[]rune("certificate1"), []rune("certificate2")},
				RequireRekorBundle: false,
				Annotations:        nil,
			},
			expectedPayload:    `{"type":"SigstoreCertificateVerify","image":"myimage:latest","certificate":[99,101,114,116,105,102,105,99,97,116,101,48],"certificate_chain":[[99,101,114,116,105,102,105,99,97,116,101,49],[99,101,114,116,105,102,105,99,97,116,101,50]],"require_rekor_bundle":false,"annotations":null}`,
			checkIsTrustedFunc: CheckCertificateTrusted,
		},
	} {
		t.Run(description, func(t *testing.T) {
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
				HostCall("kubewarden", "oci", oci.V2.String(), []byte(testCase.expectedPayload)).
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

func CheckPubKeysImageTrusted(host *cap.Host, request interface{}) (bool, error) {
	requestPubKeys := request.(sigstorePubKeysVerify)
	res, err := VerifyPubKeysImage(host, requestPubKeys.Image, requestPubKeys.PubKeys, requestPubKeys.Annotations)
	if err != nil {
		return false, err
	}
	return res.IsTrusted, nil
}

func CheckKeylessExactMatchTrusted(host *cap.Host, request interface{}) (bool, error) {
	requestKeylessExactMatch := request.(sigstoreKeylessVerifyExact)
	res, err := VerifyKeylessExactMatch(host, requestKeylessExactMatch.Image, requestKeylessExactMatch.Keyless, requestKeylessExactMatch.Annotations)
	if err != nil {
		return false, err
	}
	return res.IsTrusted, nil
}

func CheckKeylessPrefixMatchTrusted(host *cap.Host, request interface{}) (bool, error) {
	requestKeylessPrefixMatch := request.(sigstoreKeylessPrefixVerify)
	res, err := VerifyKeylessPrefixMatch(host, requestKeylessPrefixMatch.Image, requestKeylessPrefixMatch.KeylessPrefix, requestKeylessPrefixMatch.Annotations)
	if err != nil {
		return false, err
	}
	return res.IsTrusted, nil
}

func CheckKeylessGithubActionsTrusted(host *cap.Host, request interface{}) (bool, error) {
	requestKeylessGithubActions := request.(sigstoreGithubActionsVerify)
	res, err := VerifyKeylessGithubActions(host, requestKeylessGithubActions.Image, requestKeylessGithubActions.Owner, requestKeylessGithubActions.Repo, requestKeylessGithubActions.Annotations)
	if err != nil {
		return false, err
	}
	return res.IsTrusted, nil
}

func CheckCertificateTrusted(host *cap.Host, request interface{}) (bool, error) {
	requestCertificate := request.(sigstoreCertificateVerify)

	res, err := VerifyCertificate(host, requestCertificate.Image, requestCertificate.Certificate, requestCertificate.CertificateChain, requestCertificate.RequireRekorBundle, requestCertificate.Annotations)
	if err != nil {
		return false, err
	}
	return res.IsTrusted, nil
}
