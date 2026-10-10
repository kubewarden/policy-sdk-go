package cache

import (
	"encoding/json"
	"fmt"

	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"
)

// Set stores value under key in the policy-controlled cache, keeping it for ttl
// seconds.
//
// Keys reserved for Kubewarden's internal caches (those starting with
// "kubewarden_internal_") are rejected by the host.
func Set(host *capabilities.Host, key string, value []byte, ttl uint64) error {
	request := setRequest{
		Key:   key,
		TTL:   ttl,
		Value: bytesToRunes(value),
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("cannot serialize cache.set request to JSON: %w", err)
	}

	responsePayload, err := host.Client.HostCall("kubewarden", "cache", "set", payload)
	if err != nil {
		return err
	}

	response := setResponse{}
	if err = json.Unmarshal(responsePayload, &response); err != nil {
		return fmt.Errorf("cannot unmarshall cache.set response: %w", err)
	}
	if response.Code != 0 {
		return fmt.Errorf("cache.set failed: %s", response.Message)
	}

	return nil
}

// Get retrieves the value stored under key. It returns (nil, nil) on a cache
// miss; a miss is not an error.
func Get(host *capabilities.Host, key string) ([]byte, error) {
	request := getRequest{Key: key}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("cannot serialize cache.get request to JSON: %w", err)
	}

	responsePayload, err := host.Client.HostCall("kubewarden", "cache", "get", payload)
	if err != nil {
		return nil, err
	}

	response := getResponse{}
	if err = json.Unmarshal(responsePayload, &response); err != nil {
		return nil, fmt.Errorf("cannot unmarshall cache.get response: %w", err)
	}
	if response.Code != 0 {
		return nil, fmt.Errorf("cache.get failed: %s", response.Message)
	}
	if response.Value == nil {
		return nil, nil
	}

	return runesToBytes(response.Value), nil
}

func bytesToRunes(b []byte) []rune {
	runes := make([]rune, len(b))
	for i, v := range b {
		runes[i] = rune(v)
	}
	return runes
}

func runesToBytes(r []rune) []byte {
	b := make([]byte, len(r))
	for i, v := range r {
		b[i] = byte(v)
	}
	return b
}
