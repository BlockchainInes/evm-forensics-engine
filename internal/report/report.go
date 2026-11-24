package report

import (
	"encoding/json"
	"io"

	"evm-forensics-engine/internal/detection"
	"evm-forensics-engine/internal/flow"
)

const SchemaVersion = "1.1.0"

type Scope struct {
	ChainID       string `json:"chain_id"`
	FromBlock     uint64 `json:"from_block"`
	ToBlock       uint64 `json:"to_block"`
	TokenFilter   string `json:"token_filter"`
	WindowBlocks  uint64 `json:"window_blocks"`
	MinRecipients int    `json:"min_recipients"`
	MaxCycleHops  int    `json:"max_cycle_hops"`
}

type Summary struct {
	Transfers         int `json:"transfers"`
	Approvals         int `json:"approvals"`
	AddressFlows      int `json:"address_flows"`
	DuplicateEvents   int `json:"duplicate_events"`
	UnsupportedEvents int `json:"unsupported_events"`
	Findings          int `json:"findings"`
}

type Report struct {
	SchemaVersion string              `json:"schema_version"`
	Engine        string              `json:"engine"`
	Scope         Scope               `json:"scope"`
	Summary       Summary             `json:"summary"`
	AddressFlows  []flow.AddressFlow  `json:"address_flows"`
	Findings      []detection.Finding `json:"findings"`
	Limitations   []string            `json:"limitations"`
}

func New(scope Scope, snapshot flow.Snapshot, findings []detection.Finding) Report {
	if findings == nil {
		findings = make([]detection.Finding, 0)
	}
	addressFlows := snapshot.Balances
	if addressFlows == nil {
		addressFlows = make([]flow.AddressFlow, 0)
	}
	return Report{
		SchemaVersion: SchemaVersion,
		Engine:        "evm-forensics-engine",
		Scope:         scope,
		Summary: Summary{
			Transfers:         len(snapshot.Transfers),
			Approvals:         len(snapshot.Approvals),
			AddressFlows:      len(addressFlows),
			DuplicateEvents:   snapshot.DuplicateEvents,
			UnsupportedEvents: snapshot.UnsupportedEvents,
			Findings:          len(findings),
		},
		AddressFlows: addressFlows,
		Findings:     findings,
		Limitations: []string{
			"Analysis is restricted to supplied ERC-20-compatible event logs.",
			"Event authenticity and actual token balance changes are not established.",
			"Approval-to-outflow correlation does not establish spender involvement.",
			"Fan-out and circular flows do not establish illicit activity.",
			"Circular flow search is limited to 10000 candidates per initial transfer.",
			"Canonical chain membership and finality are not independently verified.",
			"RPC response completeness is not independently established.",
			"Request pacing applies to logical ingestion requests, not individual HTTP retries.",
			"An empty token filter indicates no contract-address restriction.",
			"Absence of findings does not establish absence of suspicious activity.",
		},
	}
}

func WriteJSON(w io.Writer, value Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
