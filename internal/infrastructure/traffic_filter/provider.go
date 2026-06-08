package trafficfilter

// NfrTrafficFilterProvider реализует интерфейс application.TrafficFilterProvider
type NfrTrafficFilterProvider struct {
	// Здесь будут зависимости
}

// NewProvider создает новый экземпляр провайдера
func NewProvider() *NfrTrafficFilterProvider {
	return &NfrTrafficFilterProvider{}
}
