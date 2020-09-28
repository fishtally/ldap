// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"gopkg.in/asn1-ber.v1"
)


// Other LDAP constants
const (
	LDAPBindAuthSimple = 0
	LDAPBindAuthSASL   = 3
)

type LDAPResultCode uint64

type DeleteRequest struct {
	dn string
}
type AttributeValueAssertion struct {
	attributeDesc  string
	assertionValue string
}
type CompareRequest struct {
	dn  string
	ava []AttributeValueAssertion
}
type ExtendedRequest struct {
	requestName  string
	requestValue string
}


func getLDAPResultCode(packet *ber.Packet) (code LDAPResultCode, description string) {
	if len(packet.Children) >= 2 {
		response := packet.Children[1]
		if response.ClassType == ber.ClassApplication && response.TagType == ber.TypeConstructed && len(response.Children) == 3 {
			return LDAPResultCode(response.Children[0].Value.(uint64)), response.Children[2].Value.(string)
		}
	}

	return ErrorNetwork, "Invalid packet format"
}
