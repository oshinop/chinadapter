package kuaifan

import (
	"bytes"
	"encoding/json"
	"strconv"
	"time"
)

func requiredString(fields map[string]json.RawMessage, name string) (string, error) {
	return requiredStringLimit(fields, name, maxControlFieldBytes)
}

func requiredStringLimit(fields map[string]json.RawMessage, name string, limit int) (string, error) {
	raw, ok := fields[name]
	if !ok {
		return "", ErrSchema
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value == "" || !withinLimit(value, limit) {
		return "", ErrSchema
	}
	return value, nil
}

func requiredPositiveInt32(fields map[string]json.RawMessage, name string) (int32, error) { //nolint:unparam // the field name stays explicit at call sites for readability.
	raw, ok := fields[name]
	if !ok {
		return 0, ErrSchema
	}
	return parsePositiveInt32(raw, false)
}

func requiredBool(fields map[string]json.RawMessage, name string) (bool, error) {
	raw, ok := fields[name]
	if !ok {
		return false, ErrSchema
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, ErrSchema
	}
	return value, nil
}

func requiredUnixMilli(fields map[string]json.RawMessage, name string) (time.Time, error) {
	raw, ok := fields[name]
	if !ok {
		return time.Time{}, ErrSchema
	}
	var value int64
	if err := json.Unmarshal(raw, &value); err != nil || value < 0 || value > maxUnixMilli {
		return time.Time{}, ErrSchema
	}
	if value == 0 {
		return time.Time{}, nil
	}
	return time.UnixMilli(value).UTC(), nil
}

// parsePositiveInt32 accepts only a JSON number for login identifiers. Decrypted
// authority material may encode the same identifier as a JSON string.
func parsePositiveInt32(raw json.RawMessage, allowString bool) (int32, error) {
	if allowString {
		var text string
		if json.Unmarshal(raw, &text) == nil {
			return parsePositiveDecimal(text)
		}
	}
	return parsePositiveDecimal(string(raw))
}

func parsePositiveDecimal(value string) (int32, error) {
	if value == "" || !withinLimit(value, maxControlFieldBytes) {
		return 0, ErrSchema
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, ErrSchema
		}
	}
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil || parsed <= 0 {
		return 0, ErrSchema
	}
	return int32(parsed), nil
}

func formatUserID(userID int32) string { return strconv.FormatInt(int64(userID), 10) }

func withinLimit(value string, limit int) bool { return len(value) <= limit }

func optionalNestedString(fields map[string]json.RawMessage, outer, inner string) (string, bool) {
	raw, ok := fields[outer]
	if !ok {
		return "", false
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return "", false
	}
	raw, ok = object[inner]
	if !ok {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || !withinLimit(value, maxControlFieldBytes) {
		return "", false
	}
	return value, true
}

func optionalStringLimit(object map[string]json.RawMessage, limit int, names ...string) (string, bool, error) { //nolint:unparam // the presence flag mirrors requiredStringLimit; callers may ignore it.
	for _, name := range names {
		raw, exists := object[name]
		if !exists {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil || !withinLimit(value, limit) {
			return "", false, ErrInvalidLine
		}
		return value, true, nil
	}
	return "", false, nil
}

func objectID(object map[string]json.RawMessage, names ...string) (string, bool) {
	for _, name := range names {
		raw, exists := object[name]
		if !exists {
			continue
		}
		if value, ok := idValue(raw); ok {
			return value, true
		}
	}
	return "", false
}

func idValue(raw json.RawMessage) (string, bool) {
	var stringValue string
	if json.Unmarshal(raw, &stringValue) == nil && stringValue != "" {
		return stringValue, true
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var number json.Number
	if decoder.Decode(&number) == nil {
		if _, err := strconv.ParseInt(number.String(), 10, 64); err == nil {
			return number.String(), true
		}
	}
	return "", false
}

func portValue(raw json.RawMessage) (uint16, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var n json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&n); err == nil {
		port, err := strconv.ParseUint(n.String(), 10, 16)
		return uint16(port), err == nil && port != 0
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		port, err := strconv.ParseUint(text, 10, 16)
		return uint16(port), err == nil && port != 0
	}
	return 0, false
}

func integerValue(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&number) != nil {
		return 0, false
	}
	value, err := strconv.Atoi(number.String())
	return value, err == nil
}

func booleanValue(raw json.RawMessage) (bool, bool) {
	if len(raw) == 0 {
		return false, false
	}
	var value bool
	if json.Unmarshal(raw, &value) == nil {
		return value, true
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&number) == nil {
		return number.String() == "1", number.String() == "0" || number.String() == "1"
	}
	return false, false
}
