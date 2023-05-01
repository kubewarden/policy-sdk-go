package net

import (
	"encoding/json"
	"fmt"

	cap "github.com/kubewarden/policy-sdk-go/pkg/capabilities"

	"github.com/mailru/easyjson"
)

// LookupHost looks up the addresses for a given hostname via DNS
func LookupHost(h *cap.Host, host string) ([]string, error) {
	// build request, e.g: `"localhost"`
	payload, err := json.Marshal(host)
	if err != nil {
		return []string{}, fmt.Errorf("cannot serialize host to JSON: %w", err)
	}

	// perform host callback
	responsePayload, err := h.Client.HostCall("kubewarden", "net", "v1/dns_lookup_host", payload)
	if err != nil {
		return []string{}, err
	}

	response := LookupHostResponse{}
	if err := easyjson.Unmarshal(responsePayload, &response); err != nil {
		return []string{}, fmt.Errorf("cannot unmarshall response: %w", err)
	}

	return response.Ips, nil
}
