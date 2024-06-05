package net

import (
	"encoding/json"
	"testing"

	cap "github.com/kubewarden/policy-sdk-go/pkg/capabilities"

	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/mocks"
)

func TestV1DnsLookupHost(t *testing.T) {
	mockWapcClient := &mocks.MockWapcClient{}

	lookupResponse := LookupHostResponse{
		Ips: []string{"127.0.0.1"},
	}
	lookupPayload, err := json.Marshal(lookupResponse)
	if err != nil {
		t.Fatalf("cannot serialize response object: %v", err)
	}

	expectedPayload := `"localhost"`

	mockWapcClient.
		EXPECT().
		HostCall("kubewarden", "net", "v1/dns_lookup_host", []byte(expectedPayload)).
		Return(lookupPayload, nil).
		Times(1)

	host := &cap.Host{
		Client: mockWapcClient,
	}

	res, err := LookupHost(host, "localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res[0] != lookupResponse.Ips[0] {
		t.Fatalf("unexpected error")
	}
}
