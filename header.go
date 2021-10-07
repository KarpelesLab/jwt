package jwt

type Header map[string]string

func (h Header) GetAlgo() Algo {
	if v, ok := h["alg"]; ok {
		return parseAlgo(v)
	}
	return Algo("") // "invalid"
}
