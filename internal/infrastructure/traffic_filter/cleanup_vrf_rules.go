package trafficfilter

import (
	"context"
	"fmt"

	"github.com/google/nftables"
	"github.com/shamil-developer/lab-google-nft/internal/application"
)

// CleanupVRFRules удаляет все firewall-правила для указанного VNI.
// Не трогает служебные правила цепочки (например, базовые правила созданные при инициализации VRF).
func (p *NfrTrafficFilterProvider) CleanupVRFRules(ctx context.Context, req application.CleanupVRFRulesRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	table, err := p.conn.ListTableOfFamily(tableName(req.VNI), nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("table %s not found: %w", tableName(req.VNI), err)
	}

	chain, err := p.conn.ListChain(table, chainName)
	if err != nil {
		return fmt.Errorf("chain %s not found in table %s: %w", chainName, table.Name, err)
	}

	existingRules, err := p.conn.GetRules(table, chain)
	if err != nil {
		return fmt.Errorf("get rules: %w", err)
	}

	// Удаляем только правила, содержащие выражения фильтрации (verdict, payload, cmp и т.д.)
	// Пропускаем служебные правила (без выражений — например, правила политики цепочки)
	for _, r := range existingRules {
		if len(r.Exprs) > 0 {
			if err := p.conn.DelRule(r); err != nil {
				return fmt.Errorf("del rule handle %d: %w", r.Handle, err)
			}
		}
	}

	if err := p.conn.Flush(); err != nil {
		return fmt.Errorf("flush cleanup: %w", err)
	}

	return nil
}
