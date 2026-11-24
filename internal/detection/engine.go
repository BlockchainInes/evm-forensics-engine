package detection

import (
	"errors"
	"sort"

	"evm-forensics-engine/internal/decoder"
	"evm-forensics-engine/internal/flow"
)

const (
	RuleApprovalOutflow = "R-01"
	RuleRapidFanOut     = "R-02"
	RuleCircularFlow    = "R-03"
	MaxUint256          = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
)

type Config struct {
	WindowBlocks  uint64
	MinRecipients int
	MaxCycleHops  int
}

type Finding struct {
	RuleID      string          `json:"rule_id"`
	Name        string          `json:"name"`
	Token       string          `json:"token"`
	Addresses   []string        `json:"addresses"`
	StartBlock  uint64          `json:"start_block"`
	EndBlock    uint64          `json:"end_block"`
	Description string          `json:"description"`
	Evidence    []decoder.Event `json:"evidence"`
}

type Engine struct {
	config Config
}

type accountKey struct {
	token   string
	address string
}

type approvalKey struct {
	token   string
	owner   string
	spender string
}

func DefaultConfig() Config {
	return Config{
		WindowBlocks:  20,
		MinRecipients: 5,
		MaxCycleHops:  5,
	}
}

func NewEngine(config Config) (*Engine, error) {
	if config.WindowBlocks == 0 ||
		config.WindowBlocks > 1000 ||
		config.MinRecipients < 2 ||
		config.MinRecipients > 100 ||
		config.MaxCycleHops < 2 ||
		config.MaxCycleHops > 5 {
		return nil, errors.New("invalid detection configuration")
	}
	return &Engine{config: config}, nil
}

func (e *Engine) Analyze(snapshot flow.Snapshot) []Finding {
	findings := make([]Finding, 0)
	transfers := make([]decoder.Event, 0, len(snapshot.Transfers))
	for _, event := range snapshot.Transfers {
		if event.Amount == "0" ||
			event.From == flow.ZeroAddress ||
			event.To == flow.ZeroAddress ||
			event.From == event.To {
			continue
		}
		transfers = append(transfers, event)
	}
	sortEvents(transfers)
	findings = append(findings, e.detectApprovalOutflow(snapshot.Approvals, transfers)...)
	findings = append(findings, e.detectFanOut(transfers)...)
	findings = append(findings, e.detectCircularFlow(transfers)...)
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Token != b.Token {
			return a.Token < b.Token
		}
		if a.StartBlock != b.StartBlock {
			return a.StartBlock < b.StartBlock
		}
		return precedes(a.Evidence[0], b.Evidence[0])
	})
	return findings
}

func (e *Engine) detectApprovalOutflow(approvals, transfers []decoder.Event) []Finding {
	findings := make([]Finding, 0)
	events := make([]decoder.Event, 0, len(approvals)+len(transfers))
	events = append(events, approvals...)
	events = append(events, transfers...)
	sortEvents(events)
	active := make(map[approvalKey]decoder.Event)
	for _, event := range events {
		switch event.Kind {
		case decoder.Approval:
			key := approvalKey{
				token:   event.Token,
				owner:   event.From,
				spender: event.To,
			}
			delete(active, key)
			if event.Amount == MaxUint256 &&
				event.From != flow.ZeroAddress &&
				event.To != flow.ZeroAddress &&
				event.From != event.To {
				active[key] = event
			}
		case decoder.Transfer:
			for key, approval := range active {
				if !withinWindow(approval, event, e.config.WindowBlocks) {
					delete(active, key)
					continue
				}
				if key.token != event.Token || key.owner != event.From {
					continue
				}
				findings = append(findings, Finding{
					RuleID:      RuleApprovalOutflow,
					Name:        "Approval-to-Outflow Correlation",
					Token:       event.Token,
					Addresses:   uniqueAddresses(approval.From, approval.To, event.To),
					StartBlock:  approval.BlockNumber,
					EndBlock:    event.BlockNumber,
					Description: "Token outflow observed after a maximum-value approval; spender involvement is not established.",
					Evidence:    []decoder.Event{approval, event},
				})
				delete(active, key)
			}
		}
	}
	return findings
}

func (e *Engine) detectFanOut(transfers []decoder.Event) []Finding {
	findings := make([]Finding, 0)
	groups := make(map[accountKey][]decoder.Event)
	for _, event := range transfers {
		key := accountKey{token: event.Token, address: event.From}
		groups[key] = append(groups[key], event)
	}
	for _, events := range groups {
		for start := 0; start < len(events); {
			recipients := make(map[string]struct{})
			evidence := make([]decoder.Event, 0, e.config.MinRecipients)
			matched := false
			for end := start; end < len(events); end++ {
				event := events[end]
				if event.BlockNumber-events[start].BlockNumber > e.config.WindowBlocks {
					break
				}
				if _, exists := recipients[event.To]; exists {
					continue
				}
				recipients[event.To] = struct{}{}
				evidence = append(evidence, event)
				if len(recipients) < e.config.MinRecipients {
					continue
				}
				addresses := []string{events[start].From}
				for _, item := range evidence {
					addresses = append(addresses, item.To)
				}
				findings = append(findings, Finding{
					RuleID:      RuleRapidFanOut,
					Name:        "Rapid Fan-Out",
					Token:       event.Token,
					Addresses:   addresses,
					StartBlock:  events[start].BlockNumber,
					EndBlock:    event.BlockNumber,
					Description: "Multiple distinct recipients observed within the configured block window.",
					Evidence:    evidence,
				})
				start = end + 1
				matched = true
				break
			}
			if !matched {
				start++
			}
		}
	}
	return findings
}

func (e *Engine) detectCircularFlow(transfers []decoder.Event) []Finding {
	findings := make([]Finding, 0)
	outgoing := make(map[accountKey][]decoder.Event)
	for _, event := range transfers {
		key := accountKey{token: event.Token, address: event.From}
		outgoing[key] = append(outgoing[key], event)
	}
	for _, first := range transfers {
		path := []decoder.Event{first}
		visited := map[string]bool{
			first.From: true,
			first.To:   true,
		}
		budget := 10000
		cycle := e.findCycle(first, path, visited, outgoing, &budget)
		if len(cycle) == 0 {
			continue
		}
		addresses := []string{first.From}
		for _, event := range cycle {
			addresses = append(addresses, event.To)
		}
		findings = append(findings, Finding{
			RuleID:      RuleCircularFlow,
			Name:        "Circular Token Flow",
			Token:       first.Token,
			Addresses:   uniqueAddresses(addresses...),
			StartBlock:  first.BlockNumber,
			EndBlock:    cycle[len(cycle)-1].BlockNumber,
			Description: "Chronologically ordered token transfers form an address cycle; common ownership and fund provenance are not established.",
			Evidence:    cycle,
		})
	}
	return findings
}

func (e *Engine) findCycle(
	first decoder.Event,
	path []decoder.Event,
	visited map[string]bool,
	outgoing map[accountKey][]decoder.Event,
	budget *int,
) []decoder.Event {
	if len(path) >= e.config.MaxCycleHops || *budget <= 0 {
		return nil
	}
	last := path[len(path)-1]
	key := accountKey{token: first.Token, address: last.To}
	candidates := outgoing[key]
	start := sort.Search(len(candidates), func(i int) bool {
		return precedes(last, candidates[i])
	})
	for _, next := range candidates[start:] {
		if *budget <= 0 {
			return nil
		}
		*budget = *budget - 1
		if !withinWindow(first, next, e.config.WindowBlocks) {
			break
		}
		if next.To == first.From {
			result := append([]decoder.Event(nil), path...)
			return append(result, next)
		}
		if visited[next.To] {
			continue
		}
		visited[next.To] = true
		result := e.findCycle(
			first,
			append(path, next),
			visited,
			outgoing,
			budget,
		)
		delete(visited, next.To)
		if len(result) > 0 {
			return result
		}
	}
	return nil
}

func withinWindow(first, last decoder.Event, window uint64) bool {
	return precedes(first, last) &&
		last.BlockNumber-first.BlockNumber <= window
}

func precedes(a, b decoder.Event) bool {
	if a.BlockNumber != b.BlockNumber {
		return a.BlockNumber < b.BlockNumber
	}
	if a.TransactionIndex != b.TransactionIndex {
		return a.TransactionIndex < b.TransactionIndex
	}
	return a.LogIndex < b.LogIndex
}

func sortEvents(events []decoder.Event) {
	sort.SliceStable(events, func(i, j int) bool {
		return precedes(events[i], events[j])
	})
}

func uniqueAddresses(addresses ...string) []string {
	result := make([]string, 0, len(addresses))
	seen := make(map[string]bool)
	for _, address := range addresses {
		if !seen[address] {
			seen[address] = true
			result = append(result, address)
		}
	}
	return result
}
