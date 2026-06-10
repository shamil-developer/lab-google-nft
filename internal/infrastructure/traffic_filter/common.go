package trafficfilter

import (
	"bytes"
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

const (
	chainName                    = "filterchain"
	matchRegister         uint32 = 1
	maxPort                      = 65535
	portLen               uint32 = 2
	sourcePortOffset             = 0
	destinationPortOffset        = 2
)

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
	ipMatchSource ipMatchType = iota
	ipMatchDestination
)

func buildRuleExprs(r application.Rule) ([]expr.Any, error) {
	var exprs []expr.Any

	if r.Protocol != application.ProtocolUnspecified {
		protoByte, ok := protoToByte[r.Protocol]
		if !ok {
			return nil, fmt.Errorf("unsupported protocol: %d", r.Protocol)
		}

		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: matchRegister},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: matchRegister,
				Data:     []byte{protoByte},
			},
		)
	}

	if r.SourcePrefix != "" {
		ipExprs, err := buildIPMatch(ipMatchSource, r.SourcePrefix)
		if err != nil {
			return nil, fmt.Errorf("source prefix: %w", err)
		}
		exprs = append(exprs, ipExprs...)
	}

	if r.DestinationPrefix != "" {
		ipExprs, err := buildIPMatch(ipMatchDestination, r.DestinationPrefix)
		if err != nil {
			return nil, fmt.Errorf("destination prefix: %w", err)
		}
		exprs = append(exprs, ipExprs...)
	}

	supportsPortMatch := r.Protocol == application.ProtocolTCP || r.Protocol == application.ProtocolUDP

	if supportsPortMatch && r.SourcePort != nil {
		portExprs, err := buildPortMatch(sourcePortOffset, *r.SourcePort, "source")
		if err != nil {
			return nil, err
		}
		exprs = append(exprs, portExprs...)
	}

	if supportsPortMatch && r.DestinationPort != nil {
		portExprs, err := buildPortMatch(destinationPortOffset, *r.DestinationPort, "destination")
		if err != nil {
			return nil, err
		}
		exprs = append(exprs, portExprs...)
	}

	verdictKind, ok := actionToVerdict[r.Action]
	if !ok {
		return nil, fmt.Errorf("unsupported action: %d", r.Action)
	}
	exprs = append(exprs, &expr.Verdict{Kind: verdictKind})

	return exprs, nil
}

func buildPortMatch(offset uint32, port uint32, label string) ([]expr.Any, error) {
	if port > maxPort {
		return nil, fmt.Errorf("%s port out of range: %d", label, port)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))

	return []expr.Any{
		&expr.Payload{
			DestRegister: matchRegister,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       offset,
			Len:          portLen,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: matchRegister,
			Data:     portBytes,
		},
	}, nil
}

func buildIPMatch(matchType ipMatchType, prefix string) ([]expr.Any, error) {
	ip, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", prefix, err)
	}

	var ipData []byte
	var ver ipVersion

	if ipData = ip.To4(); ipData != nil {
		ver = ipv4
	} else if ipData = ip.To16(); ipData != nil {
		ver = ipv6
	} else {
		return nil, fmt.Errorf("unsupported IP version: %q", prefix)
	}

	ones, bits := ipNet.Mask.Size()
	if bits != ver.totalBits {
		return nil, fmt.Errorf("CIDR address/mask version mismatch: %q", prefix)
	}

	offset := ver.srcOffset
	if matchType == ipMatchDestination {
		offset = ver.dstOffset
	}

	matchExprs := []expr.Any{
		&expr.Payload{
			DestRegister: matchRegister,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offset,
			Len:          ver.addrLen,
		},
	}

	if ones == bits {
		matchExprs = append(matchExprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: matchRegister,
			Data:     ipData,
		})
	} else {
		mask := net.CIDRMask(ones, ver.totalBits)
		maskedIP := ip.Mask(mask)
		if ver == ipv4 {
			maskedIP = maskedIP.To4()
		}

		matchExprs = append(matchExprs, &expr.Bitwise{
			SourceRegister: matchRegister,
			DestRegister:   matchRegister,
			Len:            ver.addrLen,
			Mask:           mask,
			Xor:            make([]byte, ver.addrLen),
		})

		matchExprs = append(matchExprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: matchRegister,
			Data:     maskedIP,
		})
	}
	return matchExprs, nil
}

func exprsEqual(a, b []expr.Any) (bool, error) {
	if len(a) != len(b) {
		return false, nil
	}

	for i := range a {
		aBytes, err := expr.Marshal(byte(nftables.TableFamilyINet), a[i])
		if err != nil {
			return false, fmt.Errorf("marshal expr a[%d]: %w", i, err)
		}

		bBytes, err := expr.Marshal(byte(nftables.TableFamilyINet), b[i])
		if err != nil {
			return false, fmt.Errorf("marshal expr b[%d]: %w", i, err)
		}

		if !bytes.Equal(aBytes, bBytes) {
			return false, nil
		}
	}

	return true, nil
}

func validateRule(r application.Rule) error {
	if _, ok := actionToVerdict[r.Action]; !ok {
		return fmt.Errorf("unsupported action: %d", r.Action)
	}

	if r.Protocol == application.ProtocolUnspecified {
		return fmt.Errorf("protocol is required")
	}

	if _, ok := protoToByte[r.Protocol]; !ok {
		return fmt.Errorf("unsupported protocol: %d", r.Protocol)
	}

	if r.SourcePrefix != "" {
		if err := validateCIDR(r.SourcePrefix); err != nil {
			return fmt.Errorf("source prefix: %w", err)
		}
	}

	if r.DestinationPrefix != "" {
		if err := validateCIDR(r.DestinationPrefix); err != nil {
			return fmt.Errorf("destination prefix: %w", err)
		}
	}

	if err := validatePort(r.SourcePort, r.Protocol, "source"); err != nil {
		return err
	}
	if err := validatePort(r.DestinationPort, r.Protocol, "destination"); err != nil {
		return err
	}

	return nil
}

func validateCIDR(value string) error {
	_, _, err := net.ParseCIDR(value)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", value, err)
	}

	return nil
}

func validatePort(port *uint32, protocol application.Protocol, label string) error {
	if port == nil {
		return nil
	}

	if protocol != application.ProtocolTCP && protocol != application.ProtocolUDP {
		return fmt.Errorf("%s port can be used only with tcp or udp protocol", label)
	}

	if *port > maxPort {
		return fmt.Errorf("%s port out of range: %d", label, *port)
	}

	return nil
}
