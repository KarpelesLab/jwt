package jwt

// Header type holds values from the token's header for easy access
type Header map[string]string

// Get will return the value of the requested key from the header, or an empty
// string if the value is not found.
func (h Header) Get(key string) string {
	if h == nil {
		return ""
	}
	if v, ok := h[key]; ok {
		return v
	}
	return ""
}

// Set will update the key's value in the header and return nil. If there is
// no header (because it failed to parse, for example), Set will return an
// ErrNoHeader error. Calling Set on a nil Header will not panic.
func (h Header) Set(key, value string) error {
	if h == nil {
		return ErrNoHeader
	}
	h[key] = value
	return nil
}

// Has returns true if the key exists in the header (and there is a header),
// and can be used to test for a given key even if its value is empty.
func (h Header) Has(key string) bool {
	if h == nil {
		return false
	}
	_, ok := h[key]
	return ok
}

// GetAlgo will return a Algo based on the alg value of the header, or nil if
// the algo is invalid or unknown. This will also work with custom algo as long
// as RegisterAlgo() was called.
func (h Header) GetAlgo() Algo {
	return parseAlgo(h.Get("alg"))
}
