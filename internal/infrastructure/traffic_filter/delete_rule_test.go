package trafficfilter

import (
	"errors"

	"github.com/google/nftables"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/shamil-developer/lab-google-nft/internal/application"
)

var _ = Describe("DeleteRule", func() {
	var env *providerTestEnv

	BeforeEach(func() {
		env = newProviderTestEnv()
	})

	Context("при удалении правила", func() {
		It("должен удалить найденное правило и выполнить flush", func() {
			rule := application.Rule{
				Protocol:     application.ProtocolICMP,
				SourcePrefix: "10.0.0.0/24",
				Action:       application.ActionDrop,
			}
			targetExprs, err := buildRuleExprs(rule)
			Expect(err).ToNot(HaveOccurred())
			existingRule := &nftables.Rule{Table: env.table, Chain: env.chain, Exprs: targetExprs}

			expectRuleLookup(env.conn, env.table, env.chain, []*nftables.Rule{existingRule})
			env.conn.EXPECT().DelRule(existingRule).Return(nil)
			env.conn.EXPECT().Flush().Return(nil)

			err = env.provider.DeleteRule(env.ctx, application.DeleteRuleRequest{VNI: 100, Rule: rule})

			Expect(err).ToNot(HaveOccurred())
		})

		It("должен ничего не делать, если правило не найдено", func() {
			rule := application.Rule{
				Protocol: application.ProtocolICMP,
				Action:   application.ActionDrop,
			}

			expectRuleLookup(env.conn, env.table, env.chain, nil)

			err := env.provider.DeleteRule(env.ctx, application.DeleteRuleRequest{VNI: 100, Rule: rule})

			Expect(err).ToNot(HaveOccurred())
		})

		It("должен вернуть ошибку и не обращаться к conn при невалидном request", func() {
			err := env.provider.DeleteRule(env.ctx, application.DeleteRuleRequest{})

			Expect(err).To(MatchError(ContainSubstring("validate delete rule request")))
		})

		It("должен вернуть ошибку, если не удалось удалить правило", func() {
			expectedErr := errors.New("delete failed")
			rule := application.Rule{
				Protocol: application.ProtocolICMP,
				Action:   application.ActionDrop,
			}
			targetExprs, err := buildRuleExprs(rule)
			Expect(err).ToNot(HaveOccurred())
			existingRule := &nftables.Rule{Table: env.table, Chain: env.chain, Exprs: targetExprs}

			expectRuleLookup(env.conn, env.table, env.chain, []*nftables.Rule{existingRule})
			env.conn.EXPECT().DelRule(existingRule).Return(expectedErr)

			err = env.provider.DeleteRule(env.ctx, application.DeleteRuleRequest{VNI: 100, Rule: rule})

			Expect(err).To(MatchError(ContainSubstring("delete failed")))
		})
	})
})
