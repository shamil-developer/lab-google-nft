package trafficfilter

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/nftables"
	"github.com/shamil-developer/lab-google-nft/internal/application"
)

// DeleteRule удаляет существующее правило фильтрации
func (p *NfrTrafficFilterProvider) DeleteRule(ctx context.Context, req application.DeleteRuleRequest) error {
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

	targetExprs := p.buildRuleExprs(req.Rule)
	var foundRule *nftables.Rule
	for _, r := range existingRules {
		if p.exprsEqual(r.Exprs, targetExprs) {
			foundRule = r
			break
		}
	}

	if foundRule == nil {
		slog.Info("rule not found, nothing to delete", "vni", req.VNI)
		return nil
	}

	if err := p.conn.DelRule(foundRule); err != nil {
		return fmt.Errorf("del rule: %w", err)
	}
	if err := p.conn.Flush(); err != nil {
		return fmt.Errorf("flush delete: %w", err)
	}

	return nil
}
