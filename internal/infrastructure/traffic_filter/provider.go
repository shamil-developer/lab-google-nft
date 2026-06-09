package trafficfilter

import (
	"github.com/google/nftables"
)

// NfrTrafficFilterProvider реализует интерфейс application.TrafficFilterProvider
type NfrTrafficFilterProvider struct {
	conn *nftables.Conn
}

// NewProviderWithConn создаёт провайдер с готовым nftables-соединением.
func NewProviderWithConn(conn *nftables.Conn) *NfrTrafficFilterProvider {
	return &NfrTrafficFilterProvider{conn: conn}
}
