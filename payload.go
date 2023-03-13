package jwt

import (
	"encoding/json"
	"reflect"
	"strconv"
	"time"
)

type Payload map[string]any

// Get is a safe get that will return nil if the body itself is null or the
// value is nil. If you want to check if a value exists or not, use Has().
func (b Payload) Get(key string) any {
	if b == nil {
		return nil
	}
	if v, ok := b[key]; ok {
		return v
	}
	return nil
}

// Set will set the specified value in the payload. It will return an error if
// the payload failed to parse, for example because it is not a JSON object.
func (b Payload) Set(key string, value any) error {
	if b == nil {
		return ErrNoPayload
	}
	b[key] = value
	return nil
}

// Has returns true if the payload was parsed and the key exists.
func (b Payload) Has(key string) bool {
	if b == nil {
		return false
	}
	_, ok := b[key]
	return ok
}

// GetString will get a value as a string, convert it to a string if possible
// or return an empty string if the value is not set or cannot be converted.
// GetString will return an empty string in case of failure.
func (b Payload) GetString(key string) string {
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

// GetInt will attempt to parse the requested key as an integer and return it.
// If the value is a float or any other kind of number-y value, it will be
// converted (truncated) and returned as an int, or 0 in case of failure.
func (b Payload) GetInt(key string) int64 {
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

// GetFloat will attempt to parse the requested key as a float and return it.
// If the value is an int or any other kind of number-y value, it will be
// converted to float64 and returned, or return 0 in case of failure.
func (b Payload) GetFloat(key string) float64 {
	switch v := b.Get(key).(type) {
	case string:
		res, _ := strconv.ParseFloat(v, 64)
		return res
	case float64:
		return v
	case int64:
		return float64(v)
	case json.Number:
		res, _ := v.Float64()
		return res
	case nil:
		return 0
	default:
		// use reflect
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return float64(rv.Int())
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			return float64(rv.Uint())
		case reflect.Float32, reflect.Float64:
			return rv.Float()
		}
		return 0
	}
}

// GetNumericDate will return a time value based on the requested header, or a
// zero time if the parsing failed or the key is not set. Check IsZero() for
// success.
func (b Payload) GetNumericDate(key string) time.Time {
	if !b.Has(key) {
		return time.Time{} // check IsZero() to see if invalid time was passed
	}
	return time.Unix(b.GetInt(key), 0)
}
