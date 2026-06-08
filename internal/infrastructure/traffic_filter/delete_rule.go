package trafficfilter

import (
	"context"

	"github.com/shamil-developer/lab-google-nft/internal/application"
)

// DeleteRule удаляет существующее правило фильтрации
/*
Правила такие
- через библиотеку https://github.com/google/nftables
- пришедшие правило мы смотрим в таблице которую мы ищем по правилу vrd-{vni от vxlan который закреплен за vrf}-filter
- если не нашли таблицу то вернем ошибку
- если таблица есть то идем альше
- ещем есть ли уже такое правло по совпадению парметров настройки правла то есть сверяя значние
- если такое правльно есть то удлаим
- если такое нет то лог пишем что типа и так нет и молча идем дальше
*/
func (p *NfrTrafficFilterProvider) DeleteRule(ctx context.Context, req application.DeleteRuleRequest) error {
	// TODO: Напишите код для удаления правила

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	return nil
}
