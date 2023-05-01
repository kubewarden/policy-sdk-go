package net

// We don't need to expose that to consumers of the library
// This is a glorified wrapper needed to unmarshal a list
// of string inside of TinyGo. As of release 0.29.0, unmarshal a simple
// list of string causes a runtime panic
type LookupHostResponse struct {
	// List of IP addresses associated with the host
	Ips []string `json:"ips"`
}
