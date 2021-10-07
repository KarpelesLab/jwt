package jwt

import (
	"encoding/json"
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

func (b Body) Has(key string) bool {
	if b == nil {
		return false
	}
	_, ok := b[key]
	return ok
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
	case json.Number:
		return v.String()
	case nil:
		return "" // null or non existant
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
	}
}

func (b Body) GetInt(key string) int64 {
	switch v := b.Get(key).(type) {
	case bool:
		if v {
			return 1
		} else {
			return 0
		}
	case string:
		res, _ := strconv.ParseInt(v, 0, 64)
		return res
	case float64:
		return int64(v)
	case int64:
		return v
	case json.Number:
		res, _ := v.Int64()
		return res
	case nil:
		return 0
	default:
		// use reflect
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return rv.Int()
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			return int64(rv.Uint())
		case reflect.Float32, reflect.Float64:
			return int64(rv.Float())
		}
		return 0
	}
}

// IsExpired will check if the body contains a "exp" claim and if it is in the
// future. Setting "req" to true will make IsExpired return true if "exp" is
// not set.
func (b Body) IsExpired(req bool) bool {
	if !b.Has("exp") {
		return req
	}
	exp := b.GetInt("exp")
	now := time.Now().Unix()

	return exp < now
}
