package trafficfilter

import (
	"encoding/binary"

	"github.com/google/nftables/expr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/shamil-developer/lab-google-nft/internal/application"
	"golang.org/x/sys/unix"
)

var _ = Describe("Common", func() {
	Context("при сравнении выражений", func() {
		It("должен вернуть true, если выражения одинаковые", func() {
			left := []expr.Any{verdict(expr.VerdictAccept)}
			right := []expr.Any{verdict(expr.VerdictAccept)}

			equal, err := exprsEqual(left, right)

			Expect(err).ToNot(HaveOccurred())
			Expect(equal).To(BeTrue())
		})

		It("должен вернуть false, если выражения отличаются", func() {
			cases := []struct {
				name  string
				left  []expr.Any
				right []expr.Any
			}{
				{
					name:  "разная длина",
					left:  []expr.Any{verdict(expr.VerdictAccept)},
					right: []expr.Any{},
				},
				{
					name:  "разные данные",
					left:  []expr.Any{cmp([]byte{unix.IPPROTO_TCP})},
					right: []expr.Any{cmp([]byte{unix.IPPROTO_UDP})},
				},
				{
					name:  "разный порядок",
					left:  []expr.Any{transportPayload(destinationPortOffset), cmp(portBytes(443))},
					right: []expr.Any{cmp(portBytes(443)), transportPayload(destinationPortOffset)},
				},
			}

			for _, tc := range cases {
				equal, err := exprsEqual(tc.left, tc.right)

				Expect(err).ToNot(HaveOccurred(), tc.name)
				Expect(equal).To(BeFalse(), tc.name)
			}
		})
	})

	Context("при сборке выражений правила", func() {
		It("должен собрать выражения для TCP destination port allow", func() {
			rule := application.Rule{
				Protocol:        application.ProtocolTCP,
				DestinationPort: ptrUint32(443),
				Action:          application.ActionAllow,
			}
			expected := []expr.Any{
				metaL4Proto(),
				cmp([]byte{unix.IPPROTO_TCP}),
				transportPayload(destinationPortOffset),
				cmp(portBytes(443)),
				verdict(expr.VerdictAccept),
			}

			actual, err := buildRuleExprs(rule)

			Expect(err).ToNot(HaveOccurred())
			expectExprsEqual(actual, expected)
		})

		It("должен собрать выражения для IPv4 source prefix drop", func() {
			rule := application.Rule{
				Protocol:     application.ProtocolTCP,
				SourcePrefix: "10.0.0.0/24",
				Action:       application.ActionDrop,
			}
			expected := []expr.Any{
				metaL4Proto(),
				cmp([]byte{unix.IPPROTO_TCP}),
				networkPayload(ipv4.srcOffset, ipv4.addrLen),
				bitwise(ipv4.addrLen, []byte{255, 255, 255, 0}),
				cmp([]byte{10, 0, 0, 0}),
				verdict(expr.VerdictDrop),
			}

			actual, err := buildRuleExprs(rule)

			Expect(err).ToNot(HaveOccurred())
			expectExprsEqual(actual, expected)
		})

		It("должен собрать прямое сравнение для exact IPv4 source address", func() {
			rule := application.Rule{
				SourcePrefix: "10.0.0.1/32",
				Action:       application.ActionAllow,
			}
			expected := []expr.Any{
				networkPayload(ipv4.srcOffset, ipv4.addrLen),
				cmp([]byte{10, 0, 0, 1}),
				verdict(expr.VerdictAccept),
			}

			actual, err := buildRuleExprs(rule)

			Expect(err).ToNot(HaveOccurred())
			expectExprsEqual(actual, expected)
		})

		It("должен игнорировать port-поля для ICMP", func() {
			rule := application.Rule{
				Protocol:        application.ProtocolICMP,
				DestinationPort: ptrUint32(443),
				Action:          application.ActionAllow,
			}
			expected := []expr.Any{
				metaL4Proto(),
				cmp([]byte{unix.IPPROTO_ICMP}),
				verdict(expr.VerdictAccept),
			}

			actual, err := buildRuleExprs(rule)

			Expect(err).ToNot(HaveOccurred())
			expectExprsEqual(actual, expected)
		})

		It("должен вернуть ошибку для невалидного правила", func() {
			cases := []struct {
				name        string
				rule        application.Rule
				expectedErr string
			}{
				{
					name: "неподдерживаемый protocol",
					rule: application.Rule{
						Protocol: application.Protocol(99),
						Action:   application.ActionAllow,
					},
					expectedErr: "unsupported protocol",
				},
				{
					name: "неподдерживаемый action",
					rule: application.Rule{
						Protocol: application.ProtocolTCP,
						Action:   application.Action(99),
					},
					expectedErr: "unsupported action",
				},
				{
					name: "невалидный source prefix",
					rule: application.Rule{
						SourcePrefix: "10.0.0.0/33",
						Action:       application.ActionAllow,
					},
					expectedErr: "source prefix",
				},
				{
					name: "destination port вне диапазона",
					rule: application.Rule{
						Protocol:        application.ProtocolUDP,
						DestinationPort: ptrUint32(70000),
						Action:          application.ActionAllow,
					},
					expectedErr: "destination port out of range",
				},
			}

			for _, tc := range cases {
				_, err := buildRuleExprs(tc.rule)

				Expect(err).To(MatchError(ContainSubstring(tc.expectedErr)), tc.name)
			}
		})
	})
})

func expectExprsEqual(actual, expected []expr.Any) {
	equal, err := exprsEqual(actual, expected)
	ExpectWithOffset(1, err).ToNot(HaveOccurred())
	ExpectWithOffset(1, equal).To(BeTrue())
}

func ptrUint32(v uint32) *uint32 {
	return &v
}

func metaL4Proto() *expr.Meta {
	return &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: matchRegister}
}

func cmp(data []byte) *expr.Cmp {
	return &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: matchRegister,
		Data:     data,
	}
}

func verdict(kind expr.VerdictKind) *expr.Verdict {
	return &expr.Verdict{Kind: kind}
}

func networkPayload(offset, length uint32) *expr.Payload {
	return &expr.Payload{
		DestRegister: matchRegister,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       offset,
		Len:          length,
	}
}

func transportPayload(offset uint32) *expr.Payload {
	return &expr.Payload{
		DestRegister: matchRegister,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       offset,
		Len:          portLen,
	}
}

func bitwise(length uint32, mask []byte) *expr.Bitwise {
	return &expr.Bitwise{
		SourceRegister: matchRegister,
		DestRegister:   matchRegister,
		Len:            length,
		Mask:           mask,
		Xor:            make([]byte, length),
	}
}

func portBytes(port uint32) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(port))
	return b
}
