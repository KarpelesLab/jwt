package jwt

type Header map[string]string

func (h Header) Get(key string) string {
	if h == nil {
		return ""
	}
	if v, ok := h[key]; ok {
		return v
	}
	return ""
}

func (h Header) Set(key, value string) error {
	if h == nil {
		return ErrNoHeader
	}
	h[key] = value
	return nil
}

func (h Header) Has(key string) bool {
	if h == nil {
		return false
	}
	_, ok := h[key]
	return ok
}

func (h Header) GetAlgo() Algo {
	return parseAlgo(h.Get("alg"))
}
