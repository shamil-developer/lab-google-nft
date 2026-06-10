package nftables

import (
	"context"
	"fmt"

	googlenft "github.com/google/nftables"
	"github.com/shamil-developer/lab-google-nft/internal/provider"
)

// ApplyRule добавляет новое правило фильтрации трафика
func (p *NfrTrafficFilterProvider) ApplyRule(ctx context.Context, req provider.ApplyRuleRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := validateApplyRuleRequest(req); err != nil {
		return fmt.Errorf("validate apply rule request: %w", err)
	}

	table, err := p.conn.ListTableOfFamily(tableName(req.VNI), googlenft.TableFamilyINet)
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

	targetExprs, err := buildRuleExprs(req.Rule)
	if err != nil {
		return fmt.Errorf("build rule exprs: %w", err)
	}

	for _, r := range existingRules {
		equal, err := exprsEqual(r.Exprs, targetExprs)
		if err != nil {
			return fmt.Errorf("compare rule exprs: %w", err)
		}
		if equal {
			return fmt.Errorf("rule already exists")
		}
	}

	rule := &googlenft.Rule{
		Table: table,
		Chain: chain,
		Exprs: targetExprs,
	}

	p.conn.AddRule(rule)
	if err := p.conn.Flush(); err != nil {
		return fmt.Errorf("flush rule: %w", err)
	}

	return nil
}

func validateApplyRuleRequest(req provider.ApplyRuleRequest) error {
	if req.VNI == 0 {
		return fmt.Errorf("vni is required")
	}

	return validateRule(req.Rule)
}
