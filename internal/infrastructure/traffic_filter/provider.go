package trafficfilter

import (
	"github.com/google/nftables"
)

type nftConn interface {
	ListTableOfFamily(name string, family nftables.TableFamily) (*nftables.Table, error)
	ListChain(table *nftables.Table, chain string) (*nftables.Chain, error)
	GetRules(table *nftables.Table, chain *nftables.Chain) ([]*nftables.Rule, error)
	AddRule(rule *nftables.Rule) *nftables.Rule
	DelRule(rule *nftables.Rule) error
	Flush() error
}

// NfrTrafficFilterProvider реализует интерфейс application.TrafficFilterProvider
type NfrTrafficFilterProvider struct {
	conn nftConn
}

// NewProviderWithConn создаёт провайдер с готовым nftables-соединением.
func NewProviderWithConn(conn *nftables.Conn) *NfrTrafficFilterProvider {
	return newProviderWithConn(conn)
}

func newProviderWithConn(conn nftConn) *NfrTrafficFilterProvider {
	return &NfrTrafficFilterProvider{conn: conn}
}
