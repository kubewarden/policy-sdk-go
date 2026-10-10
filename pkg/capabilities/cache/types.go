package cache

// setRequest is the payload of a kubewarden.cache.set host call.
type setRequest struct {
	// Key is the unique identifier for the data being stored.
	Key string `json:"key"`
	// TTL is the lifespan of the entry, in seconds.
	TTL uint64 `json:"ttl"`
	// Value is encoded as a JSON array of numbers (like crypto.Certificate.Data),
	// because the host expects a Vec<u8>; a Go []byte would marshal to base64.
	Value []rune `json:"value"`
}

// getRequest is the payload of a kubewarden.cache.get host call.
type getRequest struct {
	// Key is the key of the data to retrieve.
	Key string `json:"key"`
}

// setResponse is the response of a kubewarden.cache.set host call.
type setResponse struct {
	// Code is 0 on success, non-zero otherwise.
	Code uint32 `json:"code"`
	// Message is a human readable description of the outcome.
	Message string `json:"message"`
}

// getResponse is the response of a kubewarden.cache.get host call.
type getResponse struct {
	// Code is 0 on success, non-zero otherwise.
	Code uint32 `json:"code"`
	// Message is a human readable description of the outcome.
	Message string `json:"message"`
	// Value is the stored data, or nil on a cache miss.
	Value []rune `json:"value"`
}
