package detection

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"evm-forensics-engine/internal/decoder"
	"evm-forensics-engine/internal/flow"
)

var (
	tokenA = "0x" + strings.Repeat("a", 40)
	tokenB = "0x" + strings.Repeat("b", 40)
	addrA  = "0x" + strings.Repeat("1", 40)
	addrB  = "0x" + strings.Repeat("2", 40)
	addrC  = "0x" + strings.Repeat("3", 40)
	addrD  = "0x" + strings.Repeat("4", 40)
	addrE  = "0x" + strings.Repeat("5", 40)
	addrF  = "0x" + strings.Repeat("6", 40)
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := NewEngine(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func transfer(token, from, to string, block, index uint64) decoder.Event {
	return decoder.Event{
		Kind:             decoder.Transfer,
		Token:            token,
		From:             from,
		To:               to,
		Amount:           "100",
		BlockNumber:      block,
		BlockHash:        fmt.Sprintf("0x%064x", block),
		TransactionHash:  fmt.Sprintf("0x%032x%032x", block, index),
		TransactionIndex: index,
		LogIndex:         index,
	}
}

func approval(token, owner, spender string, block, index uint64) decoder.Event {
	event := transfer(token, owner, spender, block, index)
	event.Kind = decoder.Approval
	event.Amount = MaxUint256
	return event
}

func selectRule(findings []Finding, rule string) []Finding {
	result := make([]Finding, 0)
	for _, finding := range findings {
		if finding.RuleID == rule {
			result = append(result, finding)
		}
	}
	return result
}

func TestApprovalOutflow(t *testing.T) {
	engine := testEngine(t)
	snapshot := flow.Snapshot{
		Approvals: []decoder.Event{
			approval(tokenA, addrA, addrB, 10, 0),
		},
		Transfers: []decoder.Event{
			transfer(tokenA, addrA, addrC, 15, 0),
		},
	}
	findings := selectRule(engine.Analyze(snapshot), RuleApprovalOutflow)
	if len(findings) != 1 {
		t.Fatalf("unexpected findings: %d", len(findings))
	}
	finding := findings[0]
	if len(finding.Evidence) != 2 ||
		finding.StartBlock != 10 ||
		finding.EndBlock != 15 ||
		finding.Token != tokenA {
		t.Fatalf("invalid finding: %+v", finding)
	}
}

func TestApprovalOutflowBoundaries(t *testing.T) {
	engine := testEngine(t)
	tests := []struct {
		name  string
		block uint64
		index uint64
		token string
		want  int
	}{
		{"same_block_after", 10, 2, tokenA, 1},
		{"same_block_before", 10, 0, tokenA, 0},
		{"window_boundary", 30, 0, tokenA, 1},
		{"outside_window", 31, 0, tokenA, 0},
		{"before_approval", 9, 0, tokenA, 0},
		{"different_token", 15, 0, tokenB, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snapshot := flow.Snapshot{
				Approvals: []decoder.Event{
					approval(tokenA, addrA, addrB, 10, 1),
				},
				Transfers: []decoder.Event{
					transfer(tt.token, addrA, addrC, tt.block, tt.index),
				},
			}
			findings := selectRule(engine.Analyze(snapshot), RuleApprovalOutflow)
			if len(findings) != tt.want {
				t.Fatalf("got %d, want %d", len(findings), tt.want)
			}
		})
	}
}

func TestApprovalRevocation(t *testing.T) {
	engine := testEngine(t)
	revoked := approval(tokenA, addrA, addrB, 11, 0)
	revoked.Amount = "0"
	snapshot := flow.Snapshot{
		Approvals: []decoder.Event{
			approval(tokenA, addrA, addrB, 10, 0),
			revoked,
		},
		Transfers: []decoder.Event{
			transfer(tokenA, addrA, addrC, 12, 0),
		},
	}
	if len(selectRule(engine.Analyze(snapshot), RuleApprovalOutflow)) != 0 {
		t.Fatal("revoked approval produced a finding")
	}
}

func TestFiniteApproval(t *testing.T) {
	engine := testEngine(t)
	event := approval(tokenA, addrA, addrB, 10, 0)
	event.Amount = "1000"
	snapshot := flow.Snapshot{
		Approvals: []decoder.Event{event},
		Transfers: []decoder.Event{
			transfer(tokenA, addrA, addrC, 11, 0),
		},
	}
	if len(selectRule(engine.Analyze(snapshot), RuleApprovalOutflow)) != 0 {
		t.Fatal("finite approval produced a finding")
	}
}

func TestRapidFanOut(t *testing.T) {
	engine := testEngine(t)
	snapshot := flow.Snapshot{
		Transfers: []decoder.Event{
			transfer(tokenA, addrA, addrB, 10, 0),
			transfer(tokenA, addrA, addrC, 11, 0),
			transfer(tokenA, addrA, addrD, 12, 0),
			transfer(tokenA, addrA, addrE, 13, 0),
			transfer(tokenA, addrA, addrF, 14, 0),
		},
	}
	findings := selectRule(engine.Analyze(snapshot), RuleRapidFanOut)
	if len(findings) != 1 {
		t.Fatalf("unexpected findings: %d", len(findings))
	}
	if len(findings[0].Evidence) != 5 ||
		len(findings[0].Addresses) != 6 {
		t.Fatal("invalid fan-out evidence")
	}
}

func TestFanOutDistinctRecipients(t *testing.T) {
	engine := testEngine(t)
	snapshot := flow.Snapshot{}
	for i := uint64(0); i < 10; i++ {
		snapshot.Transfers = append(snapshot.Transfers,
			transfer(tokenA, addrA, addrB, 10, i))
	}
	if len(selectRule(engine.Analyze(snapshot), RuleRapidFanOut)) != 0 {
		t.Fatal("repeated recipient produced a finding")
	}
}

func TestFanOutWindow(t *testing.T) {
	engine := testEngine(t)
	snapshot := flow.Snapshot{
		Transfers: []decoder.Event{
			transfer(tokenA, addrA, addrB, 10, 0),
			transfer(tokenA, addrA, addrC, 11, 0),
			transfer(tokenA, addrA, addrD, 12, 0),
			transfer(tokenA, addrA, addrE, 13, 0),
			transfer(tokenA, addrA, addrF, 31, 0),
		},
	}
	if len(selectRule(engine.Analyze(snapshot), RuleRapidFanOut)) != 0 {
		t.Fatal("out-of-window transfer produced a finding")
	}
}

func TestCircularFlow(t *testing.T) {
	engine := testEngine(t)
	snapshot := flow.Snapshot{
		Transfers: []decoder.Event{
			transfer(tokenA, addrA, addrB, 10, 0),
			transfer(tokenA, addrB, addrC, 11, 0),
			transfer(tokenA, addrC, addrA, 12, 0),
		},
	}
	findings := selectRule(engine.Analyze(snapshot), RuleCircularFlow)
	if len(findings) != 1 {
		t.Fatalf("unexpected findings: %d", len(findings))
	}
	if len(findings[0].Evidence) != 3 ||
		len(findings[0].Addresses) != 3 {
		t.Fatal("invalid cycle evidence")
	}
}

func TestCircularFlowNegativeCases(t *testing.T) {
	engine := testEngine(t)
	tests := []struct {
		name   string
		events []decoder.Event
	}{
		{
			"open_path",
			[]decoder.Event{
				transfer(tokenA, addrA, addrB, 10, 0),
				transfer(tokenA, addrB, addrC, 11, 0),
			},
		},
		{
			"cross_token",
			[]decoder.Event{
				transfer(tokenA, addrA, addrB, 10, 0),
				transfer(tokenB, addrB, addrA, 11, 0),
			},
		},
		{
			"outside_window",
			[]decoder.Event{
				transfer(tokenA, addrA, addrB, 10, 0),
				transfer(tokenA, addrB, addrA, 31, 0),
			},
		},
		{
			"self_transfer",
			[]decoder.Event{
				transfer(tokenA, addrA, addrA, 10, 0),
			},
		},
		{
			"mint_burn",
			[]decoder.Event{
				transfer(tokenA, flow.ZeroAddress, addrA, 10, 0),
				transfer(tokenA, addrA, flow.ZeroAddress, 11, 0),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snapshot := flow.Snapshot{Transfers: tt.events}
			if len(selectRule(engine.Analyze(snapshot), RuleCircularFlow)) != 0 {
				t.Fatal("unexpected circular flow finding")
			}
		})
	}
}

func TestZeroAmountExcluded(t *testing.T) {
	engine := testEngine(t)
	event := transfer(tokenA, addrA, addrB, 10, 0)
	event.Amount = "0"
	snapshot := flow.Snapshot{
		Transfers: []decoder.Event{
			event,
			transfer(tokenA, addrB, addrA, 11, 0),
		},
	}
	if len(engine.Analyze(snapshot)) != 0 {
		t.Fatal("zero-value transfer produced a finding")
	}
}

func TestDeterministicFindings(t *testing.T) {
	engine := testEngine(t)
	first := transfer(tokenA, addrA, addrB, 10, 0)
	second := transfer(tokenA, addrB, addrC, 11, 0)
	third := transfer(tokenA, addrC, addrA, 12, 0)
	approvals := []decoder.Event{
		approval(tokenA, addrA, addrD, 9, 0),
		approval(tokenA, addrA, addrE, 9, 1),
	}
	a := flow.Snapshot{
		Approvals: approvals,
		Transfers: []decoder.Event{first, second, third},
	}
	b := flow.Snapshot{
		Approvals: approvals,
		Transfers: []decoder.Event{third, first, second},
	}
	left, err := json.Marshal(engine.Analyze(a))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		right, err := json.Marshal(engine.Analyze(b))
		if err != nil {
			t.Fatal(err)
		}
		if string(left) != string(right) {
			t.Fatal("nondeterministic findings")
		}
	}
}

func TestInvalidConfig(t *testing.T) {
	tests := []Config{
		{0, 5, 5},
		{1001, 5, 5},
		{20, 1, 5},
		{20, 101, 5},
		{20, 5, 1},
		{20, 5, 6},
	}
	for _, config := range tests {
		if _, err := NewEngine(config); err == nil {
			t.Fatalf("invalid configuration accepted: %+v", config)
		}
	}
}

func TestEmptyAnalysis(t *testing.T) {
	engine := testEngine(t)
	findings := engine.Analyze(flow.Snapshot{})
	if findings == nil || len(findings) != 0 {
		t.Fatal("invalid empty analysis")
	}
}

func BenchmarkDetection1000(b *testing.B) {
	engine, err := NewEngine(DefaultConfig())
	if err != nil {
		b.Fatal(err)
	}
	snapshot := flow.Snapshot{
		Transfers: make([]decoder.Event, 1000),
	}
	for i := range snapshot.Transfers {
		snapshot.Transfers[i] = transfer(
			tokenA,
			addrA,
			fmt.Sprintf("0x%040x", i+100),
			uint64(i/10+1),
			uint64(i%10),
		)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Analyze(snapshot)
	}
}
