package trafficfilter

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/shamil-developer/lab-google-nft/internal/application"
	"golang.org/x/sys/unix"
)

func tableName(vni uint32) string {
	return fmt.Sprintf("vrd-%d-filter", vni)
}

// ApplyRule добавляет новое правило фильтрации трафика
func (p *NfrTrafficFilterProvider) ApplyRule(ctx context.Context, req application.ApplyRuleRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	table, err := p.conn.ListTableOfFamily(tableName(req.VNI), nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("table %s not found: %w", tableName(req.VNI), err)
	}

	chains, err := p.conn.ListChains()
	if err != nil {
		return fmt.Errorf("list chains: %w", err)
	}

	var chain *nftables.Chain
	for _, c := range chains {
		if c.Table.Name == table.Name && c.Table.Family == table.Family {
			chain = c
			break
		}
	}
	if chain == nil {
		return fmt.Errorf("no chain found in table %s", table.Name)
	}

	existingRules, err := p.conn.GetRules(table, chain)
	if err != nil {
		return fmt.Errorf("get rules: %w", err)
	}

	if p.ruleExists(existingRules, req.Rule) {
		return fmt.Errorf("rule already exists")
	}

	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: p.buildRuleExprs(req.Rule),
	}

	p.conn.AddRule(rule)
	if err := p.conn.Flush(); err != nil {
		return fmt.Errorf("flush rule: %w", err)
	}

	return nil
}

func (p *NfrTrafficFilterProvider) buildRuleExprs(r application.Rule) []expr.Any {
	var exprs []expr.Any

	// Если указан протокол (tcp/udp), добавляем payload + cmp для meta l4proto
	if r.Protocol != application.ProtocolUnspecified {
		var protoByte byte
		switch r.Protocol {
		case application.ProtocolTCP:
			protoByte = unix.IPPROTO_TCP
		case application.ProtocolUDP:
			protoByte = unix.IPPROTO_UDP
		case application.ProtocolICMP:
			protoByte = unix.IPPROTO_ICMP
		}

		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{protoByte},
			},
		)
	}

	// Source IP
	if r.SourcePrefix != "" {
		ip, ipNet, err := net.ParseCIDR(r.SourcePrefix)
		if err == nil {
			exprs = append(exprs, p.buildIPMatch(expr.PayloadBaseNetworkHeader, 12, 4, ip, ipNet, expr.CmpOpEq)...)
		}
	}

	// Destination IP
	if r.DestinationPrefix != "" {
		ip, ipNet, err := net.ParseCIDR(r.DestinationPrefix)
		if err == nil {
			offset := uint32(16) // dest IP offset in IPv4 header
			exprs = append(exprs, p.buildIPMatch(expr.PayloadBaseNetworkHeader, offset, 4, ip, ipNet, expr.CmpOpEq)...)
		}
	}

	// Source Port (только для TCP/UDP)
	if r.SourcePort != nil && (r.Protocol == application.ProtocolTCP || r.Protocol == application.ProtocolUDP) {
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(*r.SourcePort))
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       0, // source port offset in TCP/UDP header
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     portBytes,
			},
		)
	}

	// Destination Port (только для TCP/UDP)
	if r.DestinationPort != nil && (r.Protocol == application.ProtocolTCP || r.Protocol == application.ProtocolUDP) {
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(*r.DestinationPort))
		exprs = append(exprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // dest port offset in TCP/UDP header
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     portBytes,
			},
		)
	}

	// Counter
	exprs = append(exprs, &expr.Counter{})

	// Verdict (accept или drop)
	var verdictKind expr.VerdictKind
	switch r.Action {
	case application.ActionAllow:
		verdictKind = expr.VerdictAccept
	case application.ActionDrop:
		verdictKind = expr.VerdictDrop
	default:
		verdictKind = expr.VerdictDrop
	}

	exprs = append(exprs, &expr.Verdict{Kind: verdictKind})

	return exprs
}

// buildIPMatch создаёт выражения для сравнения IP-адреса с учётом маски
func (p *NfrTrafficFilterProvider) buildIPMatch(base expr.PayloadBase, offset, ipLen uint32, ip net.IP, ipNet *net.IPNet, op expr.CmpOp) []expr.Any {
	maskLen, _ := ipNet.Mask.Size()
	ones := maskLen

	if ones == 32 || ipNet.Mask == nil {
		// Точный IPv4-адрес
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

	// С маской: используем bitwise AND с маской перед сравнением
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
