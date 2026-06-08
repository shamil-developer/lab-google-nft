package trafficfilter

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/nftables"
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

// tableName возвращает имя nftables таблицы для заданного VNI.
// Формат: vrd-{vni}-filter
func tableName(vni uint32) string {
	return fmt.Sprintf("vrd-%d-filter", vni)
}

// NfrTrafficFilterProvider реализует интерфейс application.TrafficFilterProvider
type NfrTrafficFilterProvider struct {
	conn *nftables.Conn
}

// NewProviderWithConn создаёт провайдер с готовым nftables-соединением.
// conn должен быть создан снаружи: nftables.New() для прода.
func NewProviderWithConn(conn *nftables.Conn) *NfrTrafficFilterProvider {
	return &NfrTrafficFilterProvider{conn: conn}
}

// buildRuleExprs строит список nftables-выражений из нашего Rule
func (p *NfrTrafficFilterProvider) buildRuleExprs(r application.Rule) []expr.Any {
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
		ip, ipNet, err := net.ParseCIDR(r.SourcePrefix)
		if err == nil {
			exprs = append(exprs, p.buildIPMatch(expr.PayloadBaseNetworkHeader, 12, 4, ip, ipNet, expr.CmpOpEq)...)
		}
	}

	if r.DestinationPrefix != "" {
		ip, ipNet, err := net.ParseCIDR(r.DestinationPrefix)
		if err == nil {
			exprs = append(exprs, p.buildIPMatch(expr.PayloadBaseNetworkHeader, 16, 4, ip, ipNet, expr.CmpOpEq)...)
		}
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

// buildIPMatch создаёт выражения для сравнения IP-адреса с учётом маски
func (p *NfrTrafficFilterProvider) buildIPMatch(base expr.PayloadBase, offset, ipLen uint32, ip net.IP, ipNet *net.IPNet, op expr.CmpOp) []expr.Any {
	ones, _ := ipNet.Mask.Size()

	if ones == 32 || ipNet.Mask == nil {
		return []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         base,
				Offset:       offset,
				Len:          4,
			},
			&expr.Cmp{
				Op:       op,
				Register: 1,
				Data:     ip.To4(),
			},
		}
	}

	mask := net.CIDRMask(ones, 32)
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         base,
			Offset:       offset,
			Len:          4,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           mask,
			Xor:            make([]byte, 4),
		},
		&expr.Cmp{
			Op:       op,
			Register: 1,
			Data:     ip.Mask(mask).To4(),
		},
	}
}

// ruleExists проверяет, существует ли уже правило с такими же параметрами
func (p *NfrTrafficFilterProvider) ruleExists(rules []*nftables.Rule, target application.Rule) bool {
	targetExprs := p.buildRuleExprs(target)

	for _, existing := range rules {
		if p.exprsEqual(existing.Exprs, targetExprs) {
			return true
		}
	}
	return false
}

// exprsEqual сравнивает два набора выражений по их строковому представлению
func (p *NfrTrafficFilterProvider) exprsEqual(a, b []expr.Any) bool {
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
