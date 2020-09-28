package ldap

import (
	"log"
	"net"

	"gopkg.in/asn1-ber.v1"
)

func HandleAddRequest(req *ber.Packet, boundDN string, fns map[string]Adder, conn net.Conn) (resultCode LDAPResultCode) {
	if len(req.Children) != 2 {
		return LDAPResultProtocolError
	}
	var ok bool
	addReq := AddRequest{}
	addReq.DN, ok = req.Children[0].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	addReq.Attributes = []Attribute{}
	for _, attr := range req.Children[1].Children {
		if len(attr.Children) != 2 {
			return LDAPResultProtocolError
		}

		a := Attribute{}
		a.Type, ok = attr.Children[0].Value.(string)
		if !ok {
			return LDAPResultProtocolError
		}
		a.Vals = []string{}
		for _, val := range attr.Children[1].Children {
			v, ok := val.Value.(string)
			if !ok {
				return LDAPResultProtocolError
			}
			a.Vals = append(a.Vals, v)
		}
		addReq.Attributes = append(addReq.Attributes, a)
	}
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(boundDN, fnNames)
	resultCode, err := fns[fn].Add(boundDN, addReq, conn)
	if err != nil {
		log.Printf("AddFn Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}

func HandleDeleteRequest(req *ber.Packet, boundDN string, fns map[string]Deleter, conn net.Conn) (resultCode LDAPResultCode) {
	deleteDN := ber.DecodeString(req.Data.Bytes())
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(boundDN, fnNames)
	resultCode, err := fns[fn].Delete(boundDN, deleteDN, conn)
	if err != nil {
		log.Printf("DeleteFn Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}

func HandleModifyRequest(req *ber.Packet, boundDN string, fns map[string]Modifier, conn net.Conn) (resultCode LDAPResultCode) {
	if len(req.Children) != 2 {
		return LDAPResultProtocolError
	}
	var ok bool
	modReq := ModifyRequest{}
	modReq.DN, ok = req.Children[0].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	for _, change := range req.Children[1].Children {
		if len(change.Children) != 2 {
			return LDAPResultProtocolError
		}
		attr := PartialAttribute{}
		attrs := change.Children[1].Children
		if len(attrs) != 2 {
			return LDAPResultProtocolError
		}
		attr.Type, ok = attrs[0].Value.(string)
		if !ok {
			return LDAPResultProtocolError
		}
		for _, val := range attrs[1].Children {
			v, ok := val.Value.(string)
			if !ok {
				return LDAPResultProtocolError
			}
			attr.Vals = append(attr.Vals, v)
		}
		op, ok := change.Children[0].Value.(int64)
		if !ok {
			return LDAPResultProtocolError
		}
		switch op {
		default:
			log.Printf("Unrecognized Modify attribute %d", op)
			return LDAPResultProtocolError
		case AddAttribute:
			modReq.Add(attr.Type, attr.Vals)
		case DeleteAttribute:
			modReq.Delete(attr.Type, attr.Vals)
		case ReplaceAttribute:
			modReq.Replace(attr.Type, attr.Vals)
		}
	}
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(boundDN, fnNames)
	resultCode, err := fns[fn].Modify(boundDN, modReq, conn)
	if err != nil {
		log.Printf("ModifyFn Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}

func HandleCompareRequest(req *ber.Packet, boundDN string, fns map[string]Comparer, conn net.Conn) (resultCode LDAPResultCode) {
	if len(req.Children) != 2 {
		return LDAPResultProtocolError
	}
	var ok bool
	compReq := CompareRequest{}
	compReq.dn, ok = req.Children[0].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	ava := req.Children[1]
	if len(ava.Children) != 2 {
		return LDAPResultProtocolError
	}
	attr, ok := ava.Children[0].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	val, ok := ava.Children[1].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	compReq.ava = []AttributeValueAssertion{AttributeValueAssertion{attr, val}}
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(boundDN, fnNames)
	resultCode, err := fns[fn].Compare(boundDN, compReq, conn)
	if err != nil {
		log.Printf("CompareFn Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}

func HandleExtendedRequest(req *ber.Packet, boundDN string, fns map[string]Extender, conn net.Conn) (resultCode LDAPResultCode) {
	if len(req.Children) != 1 && len(req.Children) != 2 {
		return LDAPResultProtocolError
	}
	name := ber.DecodeString(req.Children[0].Data.Bytes())
	var val string
	if len(req.Children) == 2 {
		val = ber.DecodeString(req.Children[1].Data.Bytes())
	}
	extReq := ExtendedRequest{name, val}
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(boundDN, fnNames)
	resultCode, err := fns[fn].Extended(boundDN, extReq, conn)
	if err != nil {
		log.Printf("ExtendedFn Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}

func HandleAbandonRequest(req *ber.Packet, boundDN string, fns map[string]Abandoner, conn net.Conn) error {
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(boundDN, fnNames)
	err := fns[fn].Abandon(boundDN, conn)
	return err
}

func HandleModifyDNRequest(req *ber.Packet, boundDN string, fns map[string]ModifyDNr, conn net.Conn) (resultCode LDAPResultCode) {
	if len(req.Children) != 3 && len(req.Children) != 4 {
		return LDAPResultProtocolError
	}
	var ok bool
	mdnReq := ModifyDNRequest{}
	mdnReq.DN, ok = req.Children[0].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	mdnReq.NewRDN, ok = req.Children[1].Value.(string)
	if !ok {
		return LDAPResultProtocolError
	}
	mdnReq.DeleteOldRDN, ok = req.Children[2].Value.(bool)
	if !ok {
		return LDAPResultProtocolError
	}
	if len(req.Children) == 4 {
		mdnReq.NewSuperior, ok = req.Children[3].Value.(string)
		if !ok {
			return LDAPResultProtocolError
		}
	}
	fnNames := []string{}
	for k := range fns {
		fnNames = append(fnNames, k)
	}
	fn := routeFunc(boundDN, fnNames)
	resultCode, err := fns[fn].ModifyDN(boundDN, mdnReq, conn)
	if err != nil {
		log.Printf("ModifyDN Error %s", err.Error())
		return LDAPResultOperationsError
	}
	return resultCode
}
