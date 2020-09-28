// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"errors"
	"gopkg.in/asn1-ber.v1"
	"strings"
)


func ServerApplyFilter(f *ber.Packet, entry *Entry) (bool, LDAPResultCode) {
	switch FilterMap[uint64(f.Tag)] {
	default:
		//log.Fatalf("Unknown LDAP filter code: %d", f.Tag)
		return false, LDAPResultOperationsError
	case "Equality Match":
		if len(f.Children) != 2 {
			return false, LDAPResultOperationsError
		}
		attribute := f.Children[0].Value.(string)
		value := f.Children[1].Value.(string)
		for _, a := range entry.Attributes {
			if strings.ToLower(a.Name) == strings.ToLower(attribute) {
				for _, v := range a.Values {
					if strings.ToLower(v) == strings.ToLower(value) {
						return true, LDAPResultSuccess
					}
				}
			}
		}
	case "Present":
		for _, a := range entry.Attributes {
			if strings.ToLower(a.Name) == strings.ToLower(f.Data.String()) {
				return true, LDAPResultSuccess
			}
		}
	case "And":
		for _, child := range f.Children {
			ok, exitCode := ServerApplyFilter(child, entry)
			if exitCode != LDAPResultSuccess {
				return false, exitCode
			}
			if !ok {
				return false, LDAPResultSuccess
			}
		}
		return true, LDAPResultSuccess
	case "Or":
		anyOk := false
		for _, child := range f.Children {
			ok, exitCode := ServerApplyFilter(child, entry)
			if exitCode != LDAPResultSuccess {
				return false, exitCode
			} else if ok {
				anyOk = true
			}
		}
		if anyOk {
			return true, LDAPResultSuccess
		}
	case "Not":
		if len(f.Children) != 1 {
			return false, LDAPResultOperationsError
		}
		ok, exitCode := ServerApplyFilter(f.Children[0], entry)
		if exitCode != LDAPResultSuccess {
			return false, exitCode
		} else if !ok {
			return true, LDAPResultSuccess
		}
	case "Substrings":
		if len(f.Children) != 2 {
			return false, LDAPResultOperationsError
		}
		attribute := f.Children[0].Value.(string)
		bytes := f.Children[1].Children[0].Data.Bytes()
		value := string(bytes[:])
		for _, a := range entry.Attributes {
			if strings.ToLower(a.Name) == strings.ToLower(attribute) {
				for _, v := range a.Values {
					switch f.Children[1].Children[0].Tag {
					case FilterSubstringsInitial:
						if strings.HasPrefix(v, value) {
							return true, LDAPResultSuccess
						}
					case FilterSubstringsAny:
						if strings.Contains(v, value) {
							return true, LDAPResultSuccess
						}
					case FilterSubstringsFinal:
						if strings.HasSuffix(v, value) {
							return true, LDAPResultSuccess
						}
					}
				}
			}
		}
	case "FilterGreaterOrEqual": // TODO
		return false, LDAPResultOperationsError
	case "FilterLessOrEqual": // TODO
		return false, LDAPResultOperationsError
	case "FilterApproxMatch": // TODO
		return false, LDAPResultOperationsError
	case "FilterExtensibleMatch": // TODO
		return false, LDAPResultOperationsError
	}

	return false, LDAPResultSuccess
}

func GetFilterObjectClass(filter string) (string, error) {
	f, err := CompileFilter(filter)
	if err != nil {
		return "", err
	}
	return parseFilterObjectClass(f)
}
func parseFilterObjectClass(f *ber.Packet) (string, error) {
	objectClass := ""
	switch FilterMap[uint64(f.Tag)] {
	case "Equality Match":
		if len(f.Children) != 2 {
			return "", errors.New("Equality match must have only two children")
		}
		attribute := strings.ToLower(f.Children[0].Value.(string))
		value := f.Children[1].Value.(string)
		if attribute == "objectclass" {
			objectClass = strings.ToLower(value)
		}
	case "And":
		for _, child := range f.Children {
			subType, err := parseFilterObjectClass(child)
			if err != nil {
				return "", err
			}
			if len(subType) > 0 {
				objectClass = subType
			}
		}
	case "Or":
		for _, child := range f.Children {
			subType, err := parseFilterObjectClass(child)
			if err != nil {
				return "", err
			}
			if len(subType) > 0 {
				objectClass = subType
			}
		}
	case "Not":
		if len(f.Children) != 1 {
			return "", errors.New("Not filter must have only one child")
		}
		subType, err := parseFilterObjectClass(f.Children[0])
		if err != nil {
			return "", err
		}
		if len(subType) > 0 {
			objectClass = subType
		}

	}
	return strings.ToLower(objectClass), nil
}
