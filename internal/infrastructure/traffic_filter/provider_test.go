package trafficfilter

import (
	"context"

	"github.com/golang/mock/gomock"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/shamil-developer/lab-google-nft/internal/application"
)

type providerTestEnv struct {
	ctx      context.Context
	ctrl     *gomock.Controller
	conn     *MockNftConn
	provider *NfrTrafficFilterProvider
	table    *nftables.Table
	chain    *nftables.Chain
}

func newProviderTestEnv() *providerTestEnv {
	ctrl := gomock.NewController(GinkgoT())
	DeferCleanup(ctrl.Finish)

	table := &nftables.Table{Name: tableName(100), Family: nftables.TableFamilyINet}
	chain := &nftables.Chain{Name: chainName, Table: table}
	conn := NewMockNftConn(ctrl)

	return &providerTestEnv{
		ctx:      context.Background(),
		ctrl:     ctrl,
		conn:     conn,
		provider: newProviderWithConn(conn),
		table:    table,
		chain:    chain,
	}
}

func expectRuleLookup(conn *MockNftConn, table *nftables.Table, chain *nftables.Chain, rules []*nftables.Rule) {
	conn.EXPECT().
		ListTableOfFamily(table.Name, nftables.TableFamilyINet).
		Return(table, nil)
	conn.EXPECT().
		ListChain(table, chainName).
		Return(chain, nil)
	conn.EXPECT().
		GetRules(table, chain).
		Return(rules, nil)
}

func expectRuleExprs(actual []expr.Any, rule application.Rule) {
	expected, err := buildRuleExprs(rule)
	ExpectWithOffset(1, err).ToNot(HaveOccurred())
	expectExprsEqual(actual, expected)
}
