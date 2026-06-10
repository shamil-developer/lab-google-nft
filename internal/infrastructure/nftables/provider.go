package nftables

import (
	googlenft "github.com/google/nftables"
)

type NFTConn interface {
	ListTableOfFamily(name string, family googlenft.TableFamily) (*googlenft.Table, error)
	ListChain(table *googlenft.Table, chain string) (*googlenft.Chain, error)
	GetRules(table *googlenft.Table, chain *googlenft.Chain) ([]*googlenft.Rule, error)
	AddRule(rule *googlenft.Rule) *googlenft.Rule
	DelRule(rule *googlenft.Rule) error
	Flush() error
}

// NfrTrafficFilterProvider реализует интерфейс provider.TrafficFilterProvider
type NfrTrafficFilterProvider struct {
	conn NFTConn
}

// NewProviderWithConn создаёт провайдер с готовым nftables-соединением.
func NewProviderWithConn(conn NFTConn) *NfrTrafficFilterProvider {
	return newProviderWithConn(conn)
}

func newProviderWithConn(conn NFTConn) *NfrTrafficFilterProvider {
	return &NfrTrafficFilterProvider{conn: conn}
}
