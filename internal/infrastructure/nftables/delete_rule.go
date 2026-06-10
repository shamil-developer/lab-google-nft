package nftables

import (
	"context"
	"fmt"
	"log/slog"

	googlenft "github.com/google/nftables"
	"github.com/shamil-developer/lab-google-nft/internal/provider"
)

// DeleteRule удаляет существующее правило фильтрации
func (p *NfrTrafficFilterProvider) DeleteRule(ctx context.Context, req provider.DeleteRuleRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := validateDeleteRuleRequest(req); err != nil {
		return fmt.Errorf("validate delete rule request: %w", err)
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

	var foundRule *googlenft.Rule
	for _, r := range existingRules {
		equal, err := exprsEqual(r.Exprs, targetExprs)
		if err != nil {
			return fmt.Errorf("compare rule exprs: %w", err)
		}
		if equal {
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

func validateDeleteRuleRequest(req provider.DeleteRuleRequest) error {
	if req.VNI == 0 {
		return fmt.Errorf("vni is required")
	}

	return validateRule(req.Rule)
}
