package trafficfilter

import (
	"errors"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/shamil-developer/lab-google-nft/internal/application"
)

var _ = Describe("CleanupVRFRules", func() {
	var env *providerTestEnv

	BeforeEach(func() {
		env = newProviderTestEnv()
	})

	Context("при очистке правил VRF", func() {
		It("должен удалить правила с выражениями, пропустить пустые и выполнить flush", func() {
			ruleWithExprs := &nftables.Rule{
				Table: env.table,
				Chain: env.chain,
				Exprs: []expr.Any{verdict(expr.VerdictAccept)},
			}
			emptyRule := &nftables.Rule{Table: env.table, Chain: env.chain}

			expectRuleLookup(env.conn, env.table, env.chain, []*nftables.Rule{ruleWithExprs, emptyRule})
			env.conn.EXPECT().DelRule(ruleWithExprs).Return(nil)
			env.conn.EXPECT().Flush().Return(nil)

			err := env.provider.CleanupVRFRules(env.ctx, application.CleanupVRFRulesRequest{VNI: 100})

			Expect(err).ToNot(HaveOccurred())
		})

		It("должен вернуть ошибку и не обращаться к conn при невалидном request", func() {
			err := env.provider.CleanupVRFRules(env.ctx, application.CleanupVRFRulesRequest{})

			Expect(err).To(MatchError(ContainSubstring("validate cleanup vrf rules request")))
		})

		It("должен вернуть ошибку, если не удалось получить rules", func() {
			expectedErr := errors.New("get rules failed")
			env.conn.EXPECT().
				ListTableOfFamily(tableName(100), nftables.TableFamilyINet).
				Return(env.table, nil)
			env.conn.EXPECT().
				ListChain(env.table, chainName).
				Return(env.chain, nil)
			env.conn.EXPECT().
				GetRules(env.table, env.chain).
				Return(nil, expectedErr)

			err := env.provider.CleanupVRFRules(env.ctx, application.CleanupVRFRulesRequest{VNI: 100})

			Expect(err).To(MatchError(ContainSubstring("get rules failed")))
		})
	})
})
