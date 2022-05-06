// +build !wasi

// note well: we have to use the tinygo wasi target, because the wasm one is
// meant to be used inside of the browser

package host_capabilities

import (
	"encoding/json"
)

// NewNativeHostCaller creates a HostCaller in the native target, instead
// of the wasi one. Useful for tests.
func NewNativeHostCaller(mockVR VerificationResponse, mockDigest string, mockListIPs []string) HostCaller {
	return nativeHostCaller{
		mockVerificationResponse: mockVR,
		mockDigest:               mockDigest,
		mockListIPs:              mockListIPs,
	}
}

// nativeHostCaller is a HostCaller on the native target. Used as reference
// implementation, and for type checking
type nativeHostCaller struct {
	mockVerificationResponse VerificationResponse
	mockDigest               string
	mockListIPs              []string
}

func (n nativeHostCaller) GetOCIManifest(image string) (response string, err error) {
	return n.mockDigest, nil
}

func (n nativeHostCaller) LookupHost(string) ([]string, error) {
	return n.mockListIPs, nil
}

func (n nativeHostCaller) VerifyPubKeys(image string, pubKeys []string, annotations map[string]string) (vr VerificationResponse, err error) {
	// failsafe return response
	vr = VerificationResponse{
		IsTrusted: false,
		Digest:    "",
	}

	// build request
	request := sigstorePubKeysVerify{
		Image:       image,
		PubKeys:     pubKeys,
		Annotations: annotations,
	}
	var serializedRequest []byte
	if serializedRequest, err = json.Marshal(request); err != nil {
		return vr, err
	}

	// here we would do host callback with serializedRequest
	_ = serializedRequest // we don't use the serialized request
	return n.mockVerificationResponse, nil
}

func (n nativeHostCaller) VerifyKeyless(image string, keyless []KeylessInfo, annotations map[string]string) (vr VerificationResponse, err error) {
	// failsafe return response
	vr = VerificationResponse{
		IsTrusted: false,
		Digest:    "",
	}

	// build request
	request := sigstoreKeylessVerify{
		Image:       image,
		Keyless:     keyless,
		Annotations: annotations,
	}
	var serializedRequest []byte
	if serializedRequest, err = json.Marshal(request); err != nil {
		return vr, err
	}

	// here we would do host callback with serializedRequest
	_ = serializedRequest // we don't use the serialized request
	return n.mockVerificationResponse, nil
}
