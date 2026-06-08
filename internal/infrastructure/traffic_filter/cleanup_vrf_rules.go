package trafficfilter

import (
	"context"

	"github.com/shamil-developer/lab-google-nft/internal/application"
)

// CleanupVRFRules удаляет все правила для указанного VNI
/*
Правила такие
- через библиотеку https://github.com/google/nftables
- пришедшие правило мы смотрим в таблице которую мы ищем по правилу vrd-{vni от vxlan который закреплен за vrf}-filter
- если ьалтцы нет то вернем ошибку
- если таблица есть идем дальше
- удалем из чейна именно правла связанные с фаерволом думаю ты поймешь по контекту задчи
- не надо вообще все правла что есть сносить толко фаервол
*/
func (p *NfrTrafficFilterProvider) CleanupVRFRules(ctx context.Context, req application.CleanupVRFRulesRequest) error {
	// TODO: Напишите код для очистки правил VRF

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	return nil
}
