package trafficfilter

import (
	"context"
	"fmt"

	"github.com/google/nftables"
	"github.com/shamil-developer/lab-google-nft/internal/application"
)

// ApplyRule добавляет новое правило фильтрации трафика
func (p *NfrTrafficFilterProvider) ApplyRule(ctx context.Context, req application.ApplyRuleRequest) error {
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

	targetExprs := buildRuleExprs(req.Rule)
	for _, r := range existingRules {
		if exprsEqual(r.Exprs, targetExprs) {
			return fmt.Errorf("rule already exists")
		}
	}

	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: buildRuleExprs(req.Rule),
	}

	p.conn.AddRule(rule)
	if err := p.conn.Flush(); err != nil {
		return fmt.Errorf("flush rule: %w", err)
	}

	return nil
}
