package jwt

import (
	"reflect"
	"strconv"
	"time"
)

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

// GetString will get a value as a string, convert it to a string if possible
// or return an empty string if the value is not set or cannot be converted.
func (b Body) GetString(key string) string {
	switch v := b.Get(key).(type) {
	case string:
		return v
	case []byte:
		return string(v)
	case float64:
		return strconv.FormatFloat(v, 'g', -1, 64)
	case int64:
		return strconv.FormatInt(v, 64)
	default:
		// use reflect
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return strconv.FormatInt(rv.Int(), 64)
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			return strconv.FormatUint(rv.Uint(), 64)
		case reflect.Float32:
			return strconv.FormatFloat(rv.Float(), 'g', -1, 32)
		case reflect.Float64:
			return strconv.FormatFloat(rv.Float(), 'g', -1, 64)
		case reflect.Complex64:
			return strconv.FormatComplex(rv.Complex(), 'g', -1, 64)
		case reflect.Complex128:
			return strconv.FormatComplex(rv.Complex(), 'g', -1, 128)
		}
		return ""
	case nil:
		return "" // null or non existant
	}
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
