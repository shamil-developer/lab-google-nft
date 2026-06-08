package trafficfilter

import (
	"github.com/google/nftables"
)

// NfrTrafficFilterProvider реализует интерфейс application.TrafficFilterProvider
type NfrTrafficFilterProvider struct {
	conn *nftables.Conn
	cfg  Config
}

// NewProvider создает новый экземпляр провайдера с конфигурацией по умолчанию
func NewProvider() *NfrTrafficFilterProvider {
	return NewProviderWithConfig(DefaultConfig())
}

// NewProviderWithConfig создает новый экземпляр провайдера с указанной конфигурацией
func NewProviderWithConfig(cfg Config) *NfrTrafficFilterProvider {
	conn, err := nftables.New()
	if err != nil {
		panic("failed to create nftables connection: " + err.Error())
	}
	return &NfrTrafficFilterProvider{conn: conn, cfg: cfg}
}

// Config возвращает текущую конфигурацию провайдера
func (p *NfrTrafficFilterProvider) Config() Config {
	return p.cfg
}

// Close закрывает соединение с nftables
func (p *NfrTrafficFilterProvider) Close() error {
	return p.conn.CloseLasting()
}
