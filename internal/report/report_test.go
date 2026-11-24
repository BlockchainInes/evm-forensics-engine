package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"evm-forensics-engine/internal/detection"
	"evm-forensics-engine/internal/flow"
)

func TestReportSummary(t *testing.T) {
	scope := Scope{
		ChainID:       "1",
		FromBlock:     100,
		ToBlock:       120,
		TokenFilter:   "0x0000000000000000000000000000000000000001",
		WindowBlocks:  20,
		MinRecipients: 5,
		MaxCycleHops:  5,
	}
	snapshot := flow.Snapshot{
		Balances: []flow.AddressFlow{
			{
				Token:    "token",
				Address:  "address",
				Incoming: "100",
				Outgoing: "20",
				Net:      "80",
				Minted:   "0",
				Burned:   "0",
			},
		},
		DuplicateEvents:   2,
		UnsupportedEvents: 3,
	}
	findings := []detection.Finding{
		{RuleID: detection.RuleRapidFanOut},
	}
	result := New(scope, snapshot, findings)
	if result.SchemaVersion != SchemaVersion {
		t.Fatal("schema version mismatch")
	}
	if result.Engine != "evm-forensics-engine" {
		t.Fatal("engine identifier mismatch")
	}
	if result.Scope != scope {
		t.Fatal("scope mismatch")
	}
	if result.Summary.AddressFlows != 1 ||
		result.Summary.Findings != 1 ||
		result.Summary.DuplicateEvents != 2 ||
		result.Summary.UnsupportedEvents != 3 {
		t.Fatal("summary mismatch")
	}
	if len(result.Limitations) == 0 {
		t.Fatal("missing analysis limitations")
	}
}

func TestEmptyReport(t *testing.T) {
	result := New(Scope{}, flow.Snapshot{}, nil)
	if result.Findings == nil ||
		result.AddressFlows == nil {
		t.Fatal("unexpected null collection")
	}
	if result.Summary.Findings != 0 ||
		result.Summary.AddressFlows != 0 {
		t.Fatal("unexpected empty report summary")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	original := New(
		Scope{
			ChainID:       "11155111",
			FromBlock:     100,
			ToBlock:       200,
			TokenFilter:   "0x0000000000000000000000000000000000000001",
			WindowBlocks:  30,
			MinRecipients: 7,
			MaxCycleHops:  4,
		},
		flow.Snapshot{},
		nil,
	)
	var output bytes.Buffer
	if err := WriteJSON(&output, original); err != nil {
		t.Fatal(err)
	}
	var decoded Report
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Scope != original.Scope ||
		decoded.Summary != original.Summary ||
		decoded.SchemaVersion != original.SchemaVersion {
		t.Fatal("report round-trip mismatch")
	}
}

func TestReportMetadata(t *testing.T) {
	result := New(
		Scope{
			ChainID:       "11155111",
			FromBlock:     100,
			ToBlock:       200,
			TokenFilter:   "0x0000000000000000000000000000000000000001",
			WindowBlocks:  30,
			MinRecipients: 7,
			MaxCycleHops:  4,
		},
		flow.Snapshot{},
		nil,
	)
	var output bytes.Buffer
	if err := WriteJSON(&output, result); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		SchemaVersion string `json:"schema_version"`
		Scope         struct {
			ChainID       string `json:"chain_id"`
			FromBlock     uint64 `json:"from_block"`
			ToBlock       uint64 `json:"to_block"`
			TokenFilter   string `json:"token_filter"`
			WindowBlocks  uint64 `json:"window_blocks"`
			MinRecipients int    `json:"min_recipients"`
			MaxCycleHops  int    `json:"max_cycle_hops"`
		} `json:"scope"`
	}
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != "1.1.0" ||
		decoded.Scope.ChainID != "11155111" ||
		decoded.Scope.FromBlock != 100 ||
		decoded.Scope.ToBlock != 200 ||
		decoded.Scope.TokenFilter != result.Scope.TokenFilter ||
		decoded.Scope.WindowBlocks != 30 ||
		decoded.Scope.MinRecipients != 7 ||
		decoded.Scope.MaxCycleHops != 4 {
		t.Fatal("incorrect serialized analysis metadata")
	}
}

func TestUnrestrictedTokenFilter(t *testing.T) {
	result := New(
		Scope{
			ChainID:       "1",
			FromBlock:     100,
			ToBlock:       120,
			WindowBlocks:  20,
			MinRecipients: 5,
			MaxCycleHops:  5,
		},
		flow.Snapshot{},
		nil,
	)
	var output bytes.Buffer
	if err := WriteJSON(&output, result); err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Scope map[string]json.RawMessage `json:"scope"`
	}
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	value, exists := decoded.Scope["token_filter"]
	if !exists || string(value) != `""` {
		t.Fatal("unrestricted token filter not explicitly represented")
	}
}

func TestDeterministicJSON(t *testing.T) {
	result := New(Scope{}, flow.Snapshot{}, nil)
	var first bytes.Buffer
	var second bytes.Buffer
	if err := WriteJSON(&first, result); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&second, result); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("nondeterministic JSON output")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failure")
}

func TestWriteFailure(t *testing.T) {
	result := New(Scope{}, flow.Snapshot{}, nil)
	if err := WriteJSON(failingWriter{}, result); err == nil {
		t.Fatal("writer error was suppressed")
	}
}
