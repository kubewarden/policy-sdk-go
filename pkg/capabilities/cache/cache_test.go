package cache

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/mocks"
)

func TestSet(t *testing.T) {
	mockWapcClient := &mocks.MockWapcClient{}

	key := "my-key"
	value := []byte{1, 2, 3}
	var ttl uint64 = 60

	expectedPayload, err := json.Marshal(setRequest{
		Key:   key,
		TTL:   ttl,
		Value: bytesToRunes(value),
	})
	if err != nil {
		t.Fatalf("cannot serialize request: %v", err)
	}

	responsePayload, err := json.Marshal(setResponse{Code: 0, Message: "ok"})
	if err != nil {
		t.Fatalf("cannot serialize response: %v", err)
	}

	mockWapcClient.
		EXPECT().
		HostCall("kubewarden", "cache", "set", expectedPayload).
		Return(responsePayload, nil).
		Times(1)

	host := &capabilities.Host{Client: mockWapcClient}

	if err := Set(host, key, value, ttl); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetHit(t *testing.T) {
	mockWapcClient := &mocks.MockWapcClient{}

	stored := []byte{1, 2, 3}
	responsePayload, err := json.Marshal(getResponse{
		Code:    0,
		Message: "hit",
		Value:   bytesToRunes(stored),
	})
	if err != nil {
		t.Fatalf("cannot serialize response: %v", err)
	}

	expectedPayload, err := json.Marshal(getRequest{Key: "my-key"})
	if err != nil {
		t.Fatalf("cannot serialize request: %v", err)
	}

	mockWapcClient.
		EXPECT().
		HostCall("kubewarden", "cache", "get", expectedPayload).
		Return(responsePayload, nil).
		Times(1)

	host := &capabilities.Host{Client: mockWapcClient}

	res, err := Get(host, "my-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(res, stored) {
		t.Fatalf("expected %v, got %v", stored, res)
	}
}

func TestGetMiss(t *testing.T) {
	mockWapcClient := &mocks.MockWapcClient{}

	responsePayload, err := json.Marshal(getResponse{Code: 0, Message: "miss"})
	if err != nil {
		t.Fatalf("cannot serialize response: %v", err)
	}

	expectedPayload, err := json.Marshal(getRequest{Key: "absent"})
	if err != nil {
		t.Fatalf("cannot serialize request: %v", err)
	}

	mockWapcClient.
		EXPECT().
		HostCall("kubewarden", "cache", "get", expectedPayload).
		Return(responsePayload, nil).
		Times(1)

	host := &capabilities.Host{Client: mockWapcClient}

	res, err := Get(host, "absent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != nil {
		t.Fatalf("expected nil on cache miss, got %v", res)
	}
}

func TestSetRejectsReservedKey(t *testing.T) {
	mockWapcClient := &mocks.MockWapcClient{}

	responsePayload, err := json.Marshal(setResponse{
		Code:    1,
		Message: "the key prefix 'kubewarden_internal_' is reserved",
	})
	if err != nil {
		t.Fatalf("cannot serialize response: %v", err)
	}

	value := []byte{1}
	expectedPayload, err := json.Marshal(setRequest{
		Key:   "kubewarden_internal_x",
		TTL:   60,
		Value: bytesToRunes(value),
	})
	if err != nil {
		t.Fatalf("cannot serialize request: %v", err)
	}

	mockWapcClient.
		EXPECT().
		HostCall("kubewarden", "cache", "set", expectedPayload).
		Return(responsePayload, nil).
		Times(1)

	host := &capabilities.Host{Client: mockWapcClient}

	if err := Set(host, "kubewarden_internal_x", value, 60); err == nil {
		t.Fatal("expected an error for a reserved key, got nil")
	}
}
