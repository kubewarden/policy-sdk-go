package net

import (
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	mock_capabilities "github.com/kubewarden/policy-sdk-go/mock/capabilities"
	cap "github.com/kubewarden/policy-sdk-go/pkg/capabilities"
)

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

	expectedPayload := `"localhost"`

	m.
		EXPECT().
		HostCall("kubewarden", "net", "v1/dns_lookup_host", []byte(expectedPayload)).
		Return(lookupPayload, nil).
		Times(1)

	host := &cap.Host{
		Client: m,
	}

	res, err := LookupHost(host, "localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res[0] != lookupResponse.Ips[0] {
		t.Fatalf("unexpected error")
	}
}
