package trafficfilter

import (
	"context"

	"github.com/shamil-developer/lab-google-nft/internal/application"
)

// ApplyRule добавляет новое правило фильтрации трафика
/*
Правила такие
- через библиотеку https://github.com/google/nftables
- пришедшие правило мы смотрим в таблице которую мы ищем по правилу vrd-{vni от vxlan который закреплен за vrf}-filter
- если не нашли таблицу то вернем ошибку
- если таблица есть то идем альше
- ещем есть ли уже такое правло по совпадению парметров настройки правла то есть сверяя значние
- если такое правльно есть то вренем ошибку
- если такое нет то создаем
*/
func (p *NfrTrafficFilterProvider) ApplyRule(ctx context.Context, req application.ApplyRuleRequest) error {
	// TODO: Напишите код для добавления правила

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	return nil
}
