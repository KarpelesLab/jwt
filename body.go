package jwt

import "time"

type Body map[string]interface{}

// Get is a safe get that will return nil if the body itself is null
func (b Body) Get(key string) interface{} {
	if b == nil {
		return nil
	}
	if v, ok := b[key]; ok {
		return v
	}
	return nil
}

func (b Body) Set(key string, value interface{}) error {
	if b == nil {
		return ErrNoBody
	}
	b[key] = value
	return nil
}

func (b Body) IsExpired() bool {
	if exp, ok := b["exp"]; ok {
		now := time.Now().Unix()
		switch v := exp.(type) {
		case float64:
			if v < float64(now) {
				// expired
				return true
			}
		case int64:
			if v < now {
				return true
			}
		default:
			// ???
			return true // default to expired
		}
	}
	return false // no "exp", so not expired
}
