package verify_v2

import (
	"encoding/json"
	"testing"

	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/mocks"
	oci "github.com/kubewarden/policy-sdk-go/pkg/capabilities/oci"
)

type v2VerifyTestCase struct {
	request            interface{}
	expectedPayload    string
	checkIsTrustedFunc func(host *capabilities.Host, request interface{}) (bool, error)
}

func TestV2Verify(t *testing.T) {
	mockWapcClient := &mocks.MockWapcClient{}

	for description, testCase := range map[string]v2VerifyTestCase{
		"PubKeysImage": {
			request: SigstorePubKeysVerify{
				Image:       "myimage:latest",
				PubKeys:     []string{"pubkey1", "pubkey2"},
				Annotations: nil,
			},
			expectedPayload:    `{"type":"SigstorePubKeyVerify","image":"myimage:latest","pub_keys":["pubkey1","pubkey2"],"annotations":null}`,
			checkIsTrustedFunc: CheckPubKeysImageTrusted,
		},
		"KeylessExactMatch": {
			request: SigstoreKeylessVerifyExact{
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
			request: SigstoreKeylessPrefixVerify{
				Image: "myimage:latest",
				KeylessPrefix: []KeylessPrefixInfo{
					{Issuer: "https://github.com/login/oauth", UrlPrefix: "https://example.com"},
				},
				Annotations: nil,
			},
			expectedPayload:    `{"type":"SigstoreKeylessPrefixVerify","image":"myimage:latest","keyless_prefix":[{"issuer":"https://github.com/login/oauth","url_prefix":"https://example.com"}],"annotations":null}`,
			checkIsTrustedFunc: CheckKeylessPrefixMatchTrusted,
		},
		"KeylessGithubActionsWithOrgAndRepo": {
			request: SigstoreGithubActionsVerify{
				Image:       "myimage:latest",
				Owner:       "myorg",
				Repo:        "myrepo",
				Annotations: nil,
			},
			expectedPayload:    `{"type":"SigstoreGithubActionsVerify","image":"myimage:latest","owner":"myorg","repo":"myrepo","annotations":null}`,
			checkIsTrustedFunc: CheckKeylessGithubActionsTrusted,
		},
		"KeylessGithubActionsWithOrgNoRepo": {
			request: SigstoreGithubActionsVerify{
				Image:       "myimage:latest",
				Owner:       "myorg",
				Annotations: nil,
			},
			expectedPayload:    `{"type":"SigstoreGithubActionsVerify","image":"myimage:latest","owner":"myorg","annotations":null}`,
			checkIsTrustedFunc: CheckKeylessGithubActionsTrusted,
		},
		"Certificate": {
			request: SigstoreCertificateVerify{
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

			mockWapcClient.
				EXPECT().
				HostCall("kubewarden", "oci", oci.V2.String(), []byte(testCase.expectedPayload)).
				Return(verificationPayload, nil).
				Times(1)

			host := &capabilities.Host{
				Client: mockWapcClient,
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

func CheckPubKeysImageTrusted(host *capabilities.Host, request interface{}) (bool, error) {
	requestPubKeys := request.(SigstorePubKeysVerify)
	res, err := VerifyPubKeysImage(host, requestPubKeys.Image, requestPubKeys.PubKeys, requestPubKeys.Annotations)
	if err != nil {
		return false, err
	}
	return res.IsTrusted, nil
}

func CheckKeylessExactMatchTrusted(host *capabilities.Host, request interface{}) (bool, error) {
	requestKeylessExactMatch := request.(SigstoreKeylessVerifyExact)
	res, err := VerifyKeylessExactMatch(host, requestKeylessExactMatch.Image, requestKeylessExactMatch.Keyless, requestKeylessExactMatch.Annotations)
	if err != nil {
		return false, err
	}
	return res.IsTrusted, nil
}

func CheckKeylessPrefixMatchTrusted(host *capabilities.Host, request interface{}) (bool, error) {
	requestKeylessPrefixMatch := request.(SigstoreKeylessPrefixVerify)
	res, err := VerifyKeylessPrefixMatch(host, requestKeylessPrefixMatch.Image, requestKeylessPrefixMatch.KeylessPrefix, requestKeylessPrefixMatch.Annotations)
	if err != nil {
		return false, err
	}
	return res.IsTrusted, nil
}

func CheckKeylessGithubActionsTrusted(host *capabilities.Host, request interface{}) (bool, error) {
	requestKeylessGithubActions := request.(SigstoreGithubActionsVerify)
	res, err := VerifyKeylessGithubActions(host, requestKeylessGithubActions.Image, requestKeylessGithubActions.Owner, requestKeylessGithubActions.Repo, requestKeylessGithubActions.Annotations)
	if err != nil {
		return false, err
	}
	return res.IsTrusted, nil
}

func CheckCertificateTrusted(host *capabilities.Host, request interface{}) (bool, error) {
	requestCertificate := request.(SigstoreCertificateVerify)

	res, err := VerifyCertificate(host, requestCertificate.Image, requestCertificate.Certificate, requestCertificate.CertificateChain, requestCertificate.RequireRekorBundle, requestCertificate.Annotations)
	if err != nil {
		return false, err
	}
	return res.IsTrusted, nil
}
