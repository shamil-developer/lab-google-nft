package application

import "context"

// Action определяет действие для правила
type Action int32

const (
	ActionUnspecified Action = 0
	ActionAllow       Action = 1
	ActionDrop        Action = 2
)

// Protocol определяет сетевой протокол
type Protocol int32

const (
	ProtocolUnspecified Protocol = 0
	ProtocolTCP         Protocol = 1
	ProtocolUDP         Protocol = 2
	ProtocolICMP        Protocol = 3
)

type TrafficFilterProvider interface {
	ApplyRule(ctx context.Context, req ApplyRuleRequest) error
	DeleteRule(ctx context.Context, req DeleteRuleRequest) error
	CleanupVRFRules(ctx context.Context, req CleanupVRFRulesRequest) error
}

type Rule struct {
	Protocol          Protocol
	SourcePrefix      string
	DestinationPrefix string
	SourcePort        *uint32
	DestinationPort   *uint32
	Action            Action
}

type ApplyRuleRequest struct {
	VNI  uint32
	Rule Rule
}

type DeleteRuleRequest struct {
	VNI  uint32
	Rule Rule
}

type CleanupVRFRulesRequest struct {
	VNI uint32
}
