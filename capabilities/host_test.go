package capabilities

import (
	"encoding/json"
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

func TestV1IsCertificateTrusted(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock_capabilities.NewMockWapcClient(ctrl)

	cert := Certificate{
		Encoding: Pem,
		Data:     []rune(`certificate0`),
	}
	chain := []Certificate{{
		Encoding: Pem,
		Data:     []rune(`certificate1`),
	}, {
		Encoding: Pem,
		Data:     []rune(`certificate2`),
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

	host := Host{
		Client: m,
	}

	res, err := host.VerifyCert(cert, chain, not_after)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res {
		t.Fatalf("expected trusted image, got untrusted")
	}
}

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

	expectedPayload := []byte{34, 109, 121, 105, 109, 97, 103, 101, 58, 108, 97, 116, 101, 115, 116, 34}

	m.
		EXPECT().
		HostCall("kubewarden", "oci", "v1/manifest_digest", expectedPayload).
		Return(digestPayload, nil).
		Times(1)

	host := Host{
		Client: m,
	}

	res, err := host.GetOCIManifestDigest("myimage:latest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != digestResponse.Digest {
		t.Fatalf("unexpected error")
	}
}

func TestV1DnsLookupHost(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock_capabilities.NewMockWapcClient(ctrl)

	lookupResponse := LookupHostResponse{
		Ips: []string{"127.0.0.1"},
	}
	lookupPayload, err := json.Marshal(lookupResponse)
	if err != nil {
		t.Fatalf("cannot serialize response object: %v", err)
	}

	expectedPayload := []byte{34, 108, 111, 99, 97, 108, 104, 111, 115, 116, 34}

	m.
		EXPECT().
		HostCall("kubewarden", "net", "v1/dns_lookup_host", expectedPayload).
		Return(lookupPayload, nil).
		Times(1)

	host := Host{
		Client: m,
	}

	res, err := host.LookupHost("localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res[0] != lookupResponse.Ips[0] {
		t.Fatalf("unexpected error")
	}
}

func TestKubernetesListResourcesByNamespace(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock_capabilities.NewMockWapcClient(ctrl)

	expectedInputPayload := []byte{123, 34, 97, 112, 105, 95, 118, 101, 114, 115, 105, 111, 110, 34, 58, 34, 118, 49, 34, 44, 34, 107, 105, 110, 100, 34, 58, 34, 80, 111, 100, 34, 44, 34, 110, 97, 109, 101, 115, 112, 97, 99, 101, 34, 58, 34, 100, 101, 102, 97, 117, 108, 116, 34, 44, 34, 108, 97, 98, 101, 108, 95, 115, 101, 108, 101, 99, 116, 111, 114, 34, 58, 34, 97, 112, 112, 61, 110, 103, 105, 110, 120, 34, 44, 34, 102, 105, 101, 108, 100, 95, 115, 101, 108, 101, 99, 116, 111, 114, 34, 58, 34, 115, 116, 97, 116, 117, 115, 46, 112, 104, 97, 115, 101, 61, 82, 117, 110, 110, 105, 110, 103, 34, 125}

	m.
		EXPECT().
		HostCall("kubewarden", "kubernetes", "list_resources_by_namespace", expectedInputPayload).
		Return([]byte{}, nil).
		Times(1)

	host := Host{
		Client: m,
	}

	inputRequest := ListResourcesByNamespaceRequest{
		APIVersion:    "v1",
		Kind:          "Pod",
		Namespace:     "default",
		LabelSelector: "app=nginx",
		FieldSelector: "status.phase=Running",
	}

	_, err := host.ListResourcesByNamespace(inputRequest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestKubernetesListResources(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock_capabilities.NewMockWapcClient(ctrl)

	expectedInputPayload := []byte{123, 34, 97, 112, 105, 95, 118, 101, 114, 115, 105, 111, 110, 34, 58, 34, 118, 49, 34, 44, 34, 107, 105, 110, 100, 34, 58, 34, 80, 111, 100, 34, 44, 34, 108, 97, 98, 101, 108, 95, 115, 101, 108, 101, 99, 116, 111, 114, 34, 58, 34, 97, 112, 112, 61, 110, 103, 105, 110, 120, 34, 44, 34, 102, 105, 101, 108, 100, 95, 115, 101, 108, 101, 99, 116, 111, 114, 34, 58, 34, 115, 116, 97, 116, 117, 115, 46, 112, 104, 97, 115, 101, 61, 82, 117, 110, 110, 105, 110, 103, 34, 125}

	m.
		EXPECT().
		HostCall("kubewarden", "kubernetes", "list_all_resources", expectedInputPayload).
		Return([]byte{}, nil).
		Times(1)

	host := Host{
		Client: m,
	}

	inputRequest := ListAllResourcesRequest{
		APIVersion:    "v1",
		Kind:          "Pod",
		LabelSelector: "app=nginx",
		FieldSelector: "status.phase=Running",
	}

	_, err := host.ListResources(inputRequest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestKubernetesGetResource(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock_capabilities.NewMockWapcClient(ctrl)

	expectedInputPayload := []byte{123, 34, 97, 112, 105, 95, 118, 101, 114, 115, 105, 111, 110, 34, 58, 34, 118, 49, 34, 44, 34, 107, 105, 110, 100, 34, 58, 34, 80, 111, 100, 34, 44, 34, 110, 97, 109, 101, 34, 58, 34, 110, 103, 105, 110, 120, 34, 44, 34, 110, 97, 109, 101, 115, 112, 97, 99, 101, 34, 58, 34, 100, 101, 102, 97, 117, 108, 116, 34, 44, 34, 100, 105, 115, 97, 98, 108, 101, 95, 99, 97, 99, 104, 101, 34, 58, 102, 97, 108, 115, 101, 125}

	m.
		EXPECT().
		HostCall("kubewarden", "kubernetes", "get_resource", expectedInputPayload).
		Return([]byte{}, nil).
		Times(1)

	host := Host{
		Client: m,
	}

	inputRequest := GetResourceRequest{
		APIVersion:   "v1",
		Kind:         "Pod",
		Namespace:    "default",
		Name:         "nginx",
		DisableCache: false,
	}

	_, err := host.GetResource(inputRequest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
