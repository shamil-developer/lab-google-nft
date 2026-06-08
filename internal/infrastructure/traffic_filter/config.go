package trafficfilter

// Config содержит настройки для провайдера nftables
type Config struct {
	// NetlinkSocket — путь к сокету netlink для nftables.
	// По умолчанию используется стандартный путь linux /run/nftables.sock
	NetlinkSocket string `yaml:"netlink_socket"`
}

// DefaultConfig возвращает конфигурацию с дефолтными значениями
func DefaultConfig() Config {
	return Config{
		NetlinkSocket: "/run/nftables.sock",
	}
}
