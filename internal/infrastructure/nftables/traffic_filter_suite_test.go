package nftables_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	googlenft "github.com/google/nftables"
	"github.com/google/nftables/expr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	nftables "github.com/shamil-developer/lab-google-nft/internal/infrastructure/nftables"
	"github.com/shamil-developer/lab-google-nft/internal/provider"
	"golang.org/x/sys/unix"
)

func TestTrafficFilter(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Traffic Filter Suite")
}

const (
	testVNI        uint32 = 100
	testTableName         = "vrd-100-filter"
	testChainName         = "filterchain"
	testMatchReg   uint32 = 1
	testPortLen    uint32 = 2
	testSrcPortOff        = 0
	testDstPortOff        = 2
)

type providerTestEnv struct {
	ctx      context.Context
	conn     *MockNFTConn
	provider *nftables.NfrTrafficFilterProvider
	table    *googlenft.Table
	chain    *googlenft.Chain
}

func newProviderTestEnv() *providerTestEnv {
	ctrl := gomockController()
	table := &googlenft.Table{Name: testTableName, Family: googlenft.TableFamilyINet}
	chain := &googlenft.Chain{Name: testChainName, Table: table}
	conn := NewMockNFTConn(ctrl)

	return &providerTestEnv{
		ctx:      context.Background(),
		conn:     conn,
		provider: nftables.NewProviderWithConn(conn),
		table:    table,
		chain:    chain,
	}
}

func gomockController() *gomock.Controller {
	ctrl := gomock.NewController(GinkgoT())
	DeferCleanup(ctrl.Finish)
	return ctrl
}

func expectRuleLookup(conn *MockNFTConn, table *googlenft.Table, chain *googlenft.Chain, rules []*googlenft.Rule) {
	conn.EXPECT().
		ListTableOfFamily(table.Name, googlenft.TableFamilyINet).
		Return(table, nil)
	conn.EXPECT().
		ListChain(table, testChainName).
		Return(chain, nil)
	conn.EXPECT().
		GetRules(table, chain).
		Return(rules, nil)
}

func expectRuleExprs(actual []expr.Any, rule provider.Rule) {
	expected := expectedRuleExprs(rule)
	expectExprsEqual(actual, expected)
}

func expectExprsEqual(actual, expected []expr.Any) {
	ExpectWithOffset(1, actual).To(HaveLen(len(expected)))

	for i := range actual {
		actualBytes, err := expr.Marshal(byte(googlenft.TableFamilyINet), actual[i])
		ExpectWithOffset(1, err).ToNot(HaveOccurred())

		expectedBytes, err := expr.Marshal(byte(googlenft.TableFamilyINet), expected[i])
		ExpectWithOffset(1, err).ToNot(HaveOccurred())

		ExpectWithOffset(1, bytes.Equal(actualBytes, expectedBytes)).To(BeTrue())
	}
}

func expectedRuleExprs(rule provider.Rule) []expr.Any {
	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: testMatchReg},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: testMatchReg,
			Data:     []byte{expectedProtocol(rule.Protocol)},
		},
	}

	if rule.SourcePrefix != "" {
		exprs = append(exprs, expectedIPExprs(rule.SourcePrefix, true)...)
	}
	if rule.DestinationPrefix != "" {
		exprs = append(exprs, expectedIPExprs(rule.DestinationPrefix, false)...)
	}
	if rule.SourcePort != nil {
		exprs = append(exprs, expectedPortExprs(testSrcPortOff, *rule.SourcePort)...)
	}
	if rule.DestinationPort != nil {
		exprs = append(exprs, expectedPortExprs(testDstPortOff, *rule.DestinationPort)...)
	}

	exprs = append(exprs, &expr.Verdict{Kind: expectedVerdict(rule.Action)})
	return exprs
}

func expectedProtocol(protocol provider.Protocol) byte {
	switch protocol {
	case provider.ProtocolTCP:
		return unix.IPPROTO_TCP
	case provider.ProtocolUDP:
		return unix.IPPROTO_UDP
	case provider.ProtocolICMP:
		return unix.IPPROTO_ICMP
	default:
		Fail("unsupported test protocol")
		return 0
	}
}

func expectedVerdict(action provider.Action) expr.VerdictKind {
	switch action {
	case provider.ActionAllow:
		return expr.VerdictAccept
	case provider.ActionDrop:
		return expr.VerdictDrop
	default:
		Fail("unsupported test action")
		return 0
	}
}

func expectedPortExprs(offset uint32, port uint32) []expr.Any {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, uint16(port))

	return []expr.Any{
		&expr.Payload{
			DestRegister: testMatchReg,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       offset,
			Len:          testPortLen,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: testMatchReg,
			Data:     data,
		},
	}
}

func expectedIPExprs(prefix string, source bool) []expr.Any {
	ip, ipNet, err := net.ParseCIDR(prefix)
	ExpectWithOffset(1, err).ToNot(HaveOccurred())

	ipData := ip.To4()
	addrLen := uint32(4)
	totalBits := 32
	offset := uint32(12)
	if !source {
		offset = 16
	}

	if ipData == nil {
		ipData = ip.To16()
		addrLen = 16
		totalBits = 128
		offset = 8
		if !source {
			offset = 24
		}
	}

	ones, bits := ipNet.Mask.Size()
	ExpectWithOffset(1, bits).To(Equal(totalBits))

	exprs := []expr.Any{
		&expr.Payload{
			DestRegister: testMatchReg,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offset,
			Len:          addrLen,
		},
	}

	if ones == bits {
		return append(exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: testMatchReg,
			Data:     ipData,
		})
	}

	mask := net.CIDRMask(ones, totalBits)
	maskedIP := ip.Mask(mask)
	if totalBits == 32 {
		maskedIP = maskedIP.To4()
	}

	exprs = append(exprs, &expr.Bitwise{
		SourceRegister: testMatchReg,
		DestRegister:   testMatchReg,
		Len:            addrLen,
		Mask:           mask,
		Xor:            make([]byte, addrLen),
	})
	return append(exprs, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: testMatchReg,
		Data:     maskedIP,
	})
}

func ptrUint32(v uint32) *uint32 {
	return &v
}
