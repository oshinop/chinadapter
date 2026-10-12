package kuaifan

import (
	"context"
	"encoding/json"
	"net"
	"strings"
)

// Group is a validated server-defined line group.
type Group struct {
	ID   string
	Name string
}

// Line is a validated provider endpoint. Eligibility is profile-specific: the
// baseline tunnel supports WIFIIN while recovered WS rows remain metadata only.
type Line struct {
	Label     string
	Host      string
	Port      uint16
	Provider  string
	GroupID   string
	GroupName string
	Model     string
	Weight    int
	Auto      bool
	Eligible  bool
}

// Lines is the validated result of getLines.do.
type Lines struct {
	Groups []Group
	Lines  []Line
}

// FetchLines uses the login token (not the authority provider token).
func (c *Client) FetchLines(ctx context.Context, session LoginSession) (Lines, error) {
	return c.profile.fetchLines(ctx, c, session)
}

func validateLines(fields map[string]json.RawMessage) (Lines, error) {
	return validateLinesForLanguage(fields, "zh-CN")
}

func validateLinesForLanguage(fields map[string]json.RawMessage, language string) (Lines, error) {
	return validateLinesForProfile(fields, language, iosClientProfile{})
}

func validateLinesForProfile(fields map[string]json.RawMessage, language string, profile providerProfile) (Lines, error) {
	rawGroups, ok := fields["groups"]
	if !ok {
		return Lines{}, ErrSchema
	}
	rawLines, ok := fields["lines"]
	if !ok {
		return Lines{}, ErrSchema
	}
	var groupObjects []map[string]json.RawMessage
	var lineObjects []map[string]json.RawMessage
	if err := json.Unmarshal(rawGroups, &groupObjects); err != nil || groupObjects == nil || len(groupObjects) > maxGroups {
		return Lines{}, ErrSchema
	}
	if err := json.Unmarshal(rawLines, &lineObjects); err != nil || lineObjects == nil || len(lineObjects) > maxLines {
		return Lines{}, ErrSchema
	}
	groups := make([]Group, 0, len(groupObjects))
	groupIDs := make(map[string]struct{}, len(groupObjects))
	for _, object := range groupObjects {
		if len(object) > maxGroupObjectFields {
			return Lines{}, ErrSchema
		}
		id, found := objectID(object, "id", "groupId")
		if !found || !withinLimit(id, maxGroupIDBytes) {
			return Lines{}, ErrInvalidLine
		}
		if _, duplicate := groupIDs[id]; duplicate {
			return Lines{}, ErrInvalidLine
		}
		name, _, err := optionalStringLimit(object, maxLineMetadataBytes, "name", "groupName", "text")
		if err != nil {
			return Lines{}, err
		}
		groupIDs[id] = struct{}{}
		groups = append(groups, Group{ID: id, Name: name})
	}
	lines := make([]Line, 0, len(lineObjects))
	for _, object := range lineObjects {
		line, err := parseLine(object, groupIDs, language, profile)
		if err != nil {
			return Lines{}, err
		}
		lines = append(lines, line)
	}
	return Lines{Groups: groups, Lines: lines}, nil
}

func parseLine(object map[string]json.RawMessage, groupIDs map[string]struct{}, language string, profile providerProfile) (Line, error) {
	if len(object) > maxLineObjectFields {
		return Line{}, ErrSchema
	}
	host, _, err := optionalStringLimit(object, 253, "host")
	if err != nil || !validHost(host) {
		return Line{}, ErrInvalidLine
	}
	provider, _, err := optionalStringLimit(object, maxLineMetadataBytes, "provider")
	if err != nil {
		return Line{}, ErrInvalidLine
	}
	eligible, err := profile.validateLine(object, provider)
	if err != nil {
		return Line{}, err
	}
	groupID, found := objectID(object, "groupId")
	if !found || !withinLimit(groupID, maxGroupIDBytes) {
		return Line{}, ErrInvalidLine
	}
	if _, exists := groupIDs[groupID]; !exists {
		return Line{}, ErrInvalidLine
	}
	port, ok := portValue(object["port"])
	if !ok {
		return Line{}, ErrInvalidLine
	}
	label, hasLocalizedName, err := localizedLineName(object, language)
	if err != nil {
		return Line{}, err
	}
	if !hasLocalizedName {
		label, _, err = optionalStringLimit(object, maxLineMetadataBytes, "desc")
		if err != nil {
			return Line{}, err
		}
	}
	groupName, _, err := optionalStringLimit(object, maxLineMetadataBytes, "groupName")
	if err != nil {
		return Line{}, err
	}
	model, _, err := optionalStringLimit(object, maxLineMetadataBytes, "model")
	if err != nil {
		return Line{}, err
	}
	weight, _ := integerValue(object["weight"])
	auto, _ := booleanValue(object["auto"])
	return Line{Label: label, Host: host, Port: port, Provider: provider, GroupID: groupID, GroupName: groupName, Model: model, Weight: weight, Auto: auto, Eligible: eligible}, nil
}

func localizedLineName(object map[string]json.RawMessage, preferredLanguage string) (string, bool, error) {
	raw, exists := object["lineName"]
	if !exists {
		return "", false, nil
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil || entries == nil || len(entries) == 0 || len(entries) > maxLocalizedNameEntries {
		return "", false, ErrInvalidLine
	}
	fallback := ""
	preferred := ""
	preferredLocale := strings.ToLower(strings.ReplaceAll(preferredLanguage, "_", "-"))
	for _, entry := range entries {
		if len(entry) == 0 || len(entry) > maxLocalizedNameFields {
			return "", false, ErrInvalidLine
		}
		languageRaw, ok := entry["language"]
		if !ok {
			return "", false, ErrInvalidLine
		}
		var language string
		if err := json.Unmarshal(languageRaw, &language); err != nil || language == "" || !withinLimit(language, maxLocaleBytes) {
			return "", false, ErrInvalidLine
		}
		nameRaw, ok := entry["name"]
		if !ok {
			return "", false, ErrInvalidLine
		}
		var name string
		if err := json.Unmarshal(nameRaw, &name); err != nil || !withinLimit(name, maxLineMetadataBytes) {
			return "", false, ErrInvalidLine
		}
		if name == "" {
			continue
		}
		if fallback == "" {
			fallback = name
		}
		if strings.ToLower(strings.ReplaceAll(language, "_", "-")) == preferredLocale && preferred == "" {
			preferred = name
		}
	}
	if preferred != "" {
		return preferred, true, nil
	}
	return fallback, true, nil
}

func validHost(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " \t\r\n/@") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if char != '-' && (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') {
				return false
			}
		}
	}
	return true
}
