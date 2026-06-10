package trafficfilter

import (
	"errors"

	"github.com/golang/mock/gomock"
	"github.com/google/nftables"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/shamil-developer/lab-google-nft/internal/application"
)

var _ = Describe("ApplyRule", func() {
	var env *providerTestEnv

	BeforeEach(func() {
		env = newProviderTestEnv()
	})

	Context("при добавлении правила", func() {
		It("должен добавить правило и выполнить flush", func() {
			rule := application.Rule{
				Protocol:        application.ProtocolTCP,
				DestinationPort: ptrUint32(443),
				Action:          application.ActionAllow,
			}
			var addedRule *nftables.Rule

			expectRuleLookup(env.conn, env.table, env.chain, nil)
			env.conn.EXPECT().AddRule(gomock.Any()).DoAndReturn(func(rule *nftables.Rule) *nftables.Rule {
				addedRule = rule
				return rule
			})
			env.conn.EXPECT().Flush().Return(nil)

			err := env.provider.ApplyRule(env.ctx, application.ApplyRuleRequest{VNI: 100, Rule: rule})

			Expect(err).ToNot(HaveOccurred())
			Expect(addedRule).ToNot(BeNil())
			Expect(addedRule.Table).To(Equal(env.table))
			Expect(addedRule.Chain).To(Equal(env.chain))
			expectRuleExprs(addedRule.Exprs, rule)
		})

		It("должен вернуть ошибку и не добавлять дубль", func() {
			rule := application.Rule{
				Protocol:        application.ProtocolTCP,
				DestinationPort: ptrUint32(443),
				Action:          application.ActionAllow,
			}
			existingExprs, err := buildRuleExprs(rule)
			Expect(err).ToNot(HaveOccurred())
			existingRule := &nftables.Rule{Table: env.table, Chain: env.chain, Exprs: existingExprs}

			expectRuleLookup(env.conn, env.table, env.chain, []*nftables.Rule{existingRule})

			err = env.provider.ApplyRule(env.ctx, application.ApplyRuleRequest{VNI: 100, Rule: rule})

			Expect(err).To(MatchError(ContainSubstring("rule already exists")))
		})

		It("должен вернуть ошибку и не обращаться к conn при невалидном request", func() {
			err := env.provider.ApplyRule(env.ctx, application.ApplyRuleRequest{})

			Expect(err).To(MatchError(ContainSubstring("validate apply rule request")))
		})

		It("должен вернуть ошибку, если не удалось получить table", func() {
			expectedErr := errors.New("table failed")
			rule := application.Rule{
				Protocol: application.ProtocolICMP,
				Action:   application.ActionDrop,
			}
			env.conn.EXPECT().
				ListTableOfFamily(tableName(100), nftables.TableFamilyINet).
				Return(nil, expectedErr)

			err := env.provider.ApplyRule(env.ctx, application.ApplyRuleRequest{VNI: 100, Rule: rule})

			Expect(err).To(MatchError(ContainSubstring("table failed")))
		})

		It("должен вернуть ошибку, если не удалось выполнить flush", func() {
			expectedErr := errors.New("flush failed")
			rule := application.Rule{
				Protocol: application.ProtocolICMP,
				Action:   application.ActionDrop,
			}

			expectRuleLookup(env.conn, env.table, env.chain, nil)
			env.conn.EXPECT().AddRule(gomock.Any()).Return(&nftables.Rule{})
			env.conn.EXPECT().Flush().Return(expectedErr)

			err := env.provider.ApplyRule(env.ctx, application.ApplyRuleRequest{VNI: 100, Rule: rule})

			Expect(err).To(MatchError(ContainSubstring("flush failed")))
		})
	})
})
