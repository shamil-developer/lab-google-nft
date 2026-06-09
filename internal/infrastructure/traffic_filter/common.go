package trafficfilter

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/nftables/expr"
	"github.com/shamil-developer/lab-google-nft/internal/application"
	"golang.org/x/sys/unix"
)

var actionToVerdict = map[application.Action]expr.VerdictKind{
	application.ActionAllow: expr.VerdictAccept,
	application.ActionDrop:  expr.VerdictDrop,
}

var protoToByte = map[application.Protocol]byte{
	application.ProtocolTCP:  unix.IPPROTO_TCP,
	application.ProtocolUDP:  unix.IPPROTO_UDP,
	application.ProtocolICMP: unix.IPPROTO_ICMP,
}

const chainName = "filterchain"

func tableName(vni uint32) string {
	return fmt.Sprintf("vrd-%d-filter", vni)
}

type ipVersion struct {
	addrLen   uint32
	totalBits int
	srcOffset uint32
	dstOffset uint32
}

var (
	ipv4 = ipVersion{addrLen: 4, totalBits: 32, srcOffset: 12, dstOffset: 16}
	ipv6 = ipVersion{addrLen: 16, totalBits: 128, srcOffset: 8, dstOffset: 24}
)

type ipMatchType int

const (
	ipMatchSource      ipMatchType = iota
	ipMatchDestination
)

func detectIPVersion(ip net.IP) ipVersion {
	if ip.To4() != nil {
		return ipv4
	}
	return ipv6
}

func buildRuleExprs(r application.Rule) []expr.Any {
	var exprs []expr.Any

	if r.Protocol != application.ProtocolUnspecified {
		protoByte := protoToByte[r.Protocol]

		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{protoByte},
			},
		)
	}

	if r.SourcePrefix != "" {
		exprs = append(exprs, buildIPMatch(expr.PayloadBaseNetworkHeader, ipMatchSource, r.SourcePrefix, expr.CmpOpEq)...)
	}

	if r.DestinationPrefix != "" {
		exprs = append(exprs, buildIPMatch(expr.PayloadBaseNetworkHeader, ipMatchDestination, r.DestinationPrefix, expr.CmpOpEq)...)
	}

	if r.SourcePort != nil && (r.Protocol == application.ProtocolTCP || r.Protocol == application.ProtocolUDP) {
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(*r.SourcePort))
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       0,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     portBytes,
			},
		)
	}

	if r.DestinationPort != nil && (r.Protocol == application.ProtocolTCP || r.Protocol == application.ProtocolUDP) {
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(*r.DestinationPort))
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     portBytes,
			},
		)
	}

	verdictKind, ok := actionToVerdict[r.Action]
	if !ok {
		verdictKind = expr.VerdictDrop
	}
	exprs = append(exprs, &expr.Verdict{Kind: verdictKind})

	return exprs
}

func buildIPMatch(base expr.PayloadBase, matchType ipMatchType, prefix string, op expr.CmpOp) []expr.Any {
	ip, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return nil
	}

	ver := detectIPVersion(ip)
	ones, _ := ipNet.Mask.Size()

	offset := ver.srcOffset
	if matchType == ipMatchDestination {
		offset = ver.dstOffset
	}

	var ipData []byte
	if ver == ipv4 {
		ipData = ip.To4()
	} else {
		ipData = ip.To16()
	}

	if ones == ver.totalBits || ipNet.Mask == nil {
		return []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         base,
				Offset:       offset,
				Len:          ver.addrLen,
			},
			&expr.Cmp{
				Op:       op,
				Register: 1,
				Data:     ipData,
			},
		}
	}

	mask := net.CIDRMask(ones, ver.totalBits)
	maskedIP := ip.Mask(mask)
	if ver == ipv4 {
		maskedIP = maskedIP.To4()
	}

	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         base,
			Offset:       offset,
			Len:          ver.addrLen,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            ver.addrLen,
			Mask:           mask,
			Xor:            make([]byte, ver.addrLen),
		},
		&expr.Cmp{
			Op:       op,
			Register: 1,
			Data:     maskedIP,
		},
	}
}

func exprsEqual(a, b []expr.Any) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if fmt.Sprintf("%#v", a[i]) != fmt.Sprintf("%#v", b[i]) {
			return false
		}
	}
	return true
}
