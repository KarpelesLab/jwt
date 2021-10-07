package jwt

import "time"

type Body map[string]interface{}

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
