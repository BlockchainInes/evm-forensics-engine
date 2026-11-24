package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"evm-forensics-engine/internal/decoder"
	"evm-forensics-engine/internal/report"
	"evm-forensics-engine/internal/rpc"
)

func TestParseOptions(t *testing.T) {
	opts, err := parseOptions(
		[]string{
			"-from-block", "100",
			"-to-block", "120",
			"-token", "0x" + strings.Repeat("A", 40),
		},
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	if opts.fromBlock != 100 || opts.toBlock != 120 {
		t.Fatal("block range mismatch")
	}
	if opts.token != "0x"+strings.Repeat("a", 40) {
		t.Fatal("token normalization failed")
	}
	if opts.window != 20 || opts.minRecipients != 5 || opts.maxCycleHops != 5 {
		t.Fatal("default configuration mismatch")
	}
}

func TestInvalidOptions(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"missing_range", nil},
		{"missing_end", []string{"-from-block", "100"}},
		{"reversed_range", []string{"-from-block", "120", "-to-block", "100"}},
		{"oversized_range", []string{"-from-block", "0", "-to-block", "1000"}},
		{"invalid_token", []string{"-from-block", "1", "-to-block", "2", "-token", "0x1234"}},
		{"invalid_window", []string{"-from-block", "1", "-to-block", "2", "-window", "0"}},
		{"invalid_recipients", []string{"-from-block", "1", "-to-block", "2", "-min-recipients", "1"}},
		{"invalid_cycle", []string{"-from-block", "1", "-to-block", "2", "-max-cycle-hops", "6"}},
		{"invalid_timeout", []string{"-from-block", "1", "-to-block", "2", "-timeout", "0s"}},
		{"positional_argument", []string{"-from-block", "1", "-to-block", "2", "unexpected"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseOptions(tt.args, io.Discard); err == nil {
				t.Fatal("invalid options accepted")
			}
		})
	}
}

func TestMissingEndpoint(t *testing.T) {
	err := run(
		context.Background(),
		[]string{"-from-block", "100", "-to-block", "120"},
		"",
		io.Discard,
		io.Discard,
	)
	if err == nil {
		t.Fatal("missing endpoint accepted")
	}
}

func TestHelp(t *testing.T) {
	var output bytes.Buffer
	err := run(
		context.Background(),
		[]string{"-help"},
		"",
		io.Discard,
		&output,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "from-block") {
		t.Fatal("missing CLI help")
	}
}

func makeTransferLog(from, to string, block, index uint64) rpc.Log {
	return rpc.Log{
		Address: "0x" + strings.Repeat("a", 40),
		Topics: []string{
			decoder.TransferTopic,
			"0x" + strings.Repeat("0", 24) + from[2:],
			"0x" + strings.Repeat("0", 24) + to[2:],
		},
		Data:             fmt.Sprintf("0x%064x", 100),
		BlockNumber:      fmt.Sprintf("0x%x", block),
		BlockHash:        fmt.Sprintf("0x%064x", block),
		TransactionHash:  fmt.Sprintf("0x%032x%032x", block, index),
		TransactionIndex: fmt.Sprintf("0x%x", index),
		LogIndex:         fmt.Sprintf("0x%x", index),
	}
}

func mockRPC(logs []rpc.Log) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request rpc.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var result any
		switch request.Method {
		case "eth_chainId":
			result = "0x1"
		case "eth_getLogs":
			result = logs
		default:
			http.Error(w, "unsupported method", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      request.ID,
			"result":  result,
		})
	}))
}

func TestEndToEndAnalysis(t *testing.T) {
	a := "0x" + strings.Repeat("1", 40)
	b := "0x" + strings.Repeat("2", 40)
	c := "0x" + strings.Repeat("3", 40)
	logs := []rpc.Log{
		makeTransferLog(a, b, 100, 0),
		makeTransferLog(b, c, 101, 0),
		makeTransferLog(c, a, 102, 0),
	}
	server := mockRPC(logs)
	defer server.Close()
	var output bytes.Buffer
	err := run(
		context.Background(),
		[]string{"-from-block", "100", "-to-block", "120"},
		server.URL,
		&output,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	var result report.Report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	expectedScope := report.Scope{
		ChainID:       "1",
		FromBlock:     100,
		ToBlock:       120,
		TokenFilter:   "",
		WindowBlocks:  20,
		MinRecipients: 5,
		MaxCycleHops:  5,
	}
	if result.Scope != expectedScope {
		t.Fatal("default analysis scope mismatch")
	}
	if result.SchemaVersion != report.SchemaVersion {
		t.Fatal("schema version mismatch")
	}
	if result.Summary.Transfers != 3 {
		t.Fatal("transfer count mismatch")
	}
	if result.Summary.Findings != 1 || len(result.Findings) != 1 {
		t.Fatal("finding count mismatch")
	}
	if result.Findings[0].RuleID != "R-03" {
		t.Fatal("unexpected detection rule")
	}
	if len(result.Findings[0].Evidence) != 3 {
		t.Fatal("incomplete evidence")
	}
}

func TestCustomReportMetadata(t *testing.T) {
	server := mockRPC([]rpc.Log{})
	defer server.Close()
	var output bytes.Buffer
	err := run(
		context.Background(),
		[]string{
			"-from-block", "100",
			"-to-block", "120",
			"-token", "0x" + strings.Repeat("A", 40),
			"-window", "15",
			"-min-recipients", "4",
			"-max-cycle-hops", "3",
		},
		server.URL,
		&output,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	var result report.Report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	expected := report.Scope{
		ChainID:       "1",
		FromBlock:     100,
		ToBlock:       120,
		TokenFilter:   "0x" + strings.Repeat("a", 40),
		WindowBlocks:  15,
		MinRecipients: 4,
		MaxCycleHops:  3,
	}
	if result.Scope != expected {
		t.Fatalf("analysis metadata mismatch: %+v", result.Scope)
	}
	if result.SchemaVersion != "1.1.0" {
		t.Fatal("unexpected report schema version")
	}
}

func TestEmptyAnalysis(t *testing.T) {
	server := mockRPC([]rpc.Log{})
	defer server.Close()
	var output bytes.Buffer
	err := run(
		context.Background(),
		[]string{"-from-block", "100", "-to-block", "120"},
		server.URL,
		&output,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	var result report.Report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Summary.Findings != 0 || result.Summary.Transfers != 0 {
		t.Fatal("unexpected findings")
	}
}

func TestNullLogResult(t *testing.T) {
	server := mockRPC(nil)
	defer server.Close()
	var output bytes.Buffer
	err := run(
		context.Background(),
		[]string{"-from-block", "100", "-to-block", "120"},
		server.URL,
		&output,
		io.Discard,
	)
	if err == nil || output.Len() != 0 {
		t.Fatal("null result was not rejected")
	}
}

func TestInvalidRPCLogs(t *testing.T) {
	a := "0x" + strings.Repeat("1", 40)
	b := "0x" + strings.Repeat("2", 40)
	tests := []struct {
		name   string
		mutate func(*rpc.Log)
	}{
		{"outside_range", func(log *rpc.Log) {
			log.BlockNumber = "0x99"
		}},
		{"removed_log", func(log *rpc.Log) {
			log.Removed = true
		}},
		{"invalid_block", func(log *rpc.Log) {
			log.BlockNumber = "0x00"
		}},
		{"wrong_signature", func(log *rpc.Log) {
			log.Topics[0] = "0x" + strings.Repeat("f", 64)
		}},
		{"missing_signature", func(log *rpc.Log) {
			log.Topics = nil
		}},
		{"wrong_token", func(log *rpc.Log) {
			log.Address = "0x" + strings.Repeat("b", 40)
		}},
		{"invalid_log_index", func(log *rpc.Log) {
			log.LogIndex = "0x00"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := makeTransferLog(a, b, 100, 0)
			tt.mutate(&log)
			server := mockRPC([]rpc.Log{log})
			defer server.Close()
			var output bytes.Buffer
			err := run(
				context.Background(),
				[]string{
					"-from-block", "100",
					"-to-block", "120",
					"-token", "0x" + strings.Repeat("a", 40),
				},
				server.URL,
				&output,
				io.Discard,
			)
			if err == nil || output.Len() != 0 {
				t.Fatal("invalid RPC data was not rejected")
			}
		})
	}
}

func TestConflictingRPCLogs(t *testing.T) {
	a := "0x" + strings.Repeat("1", 40)
	b := "0x" + strings.Repeat("2", 40)
	tests := []struct {
		name   string
		mutate func(*rpc.Log)
	}{
		{"conflicting_block_hash", func(log *rpc.Log) {
			log.BlockHash = "0x" + strings.Repeat("f", 64)
			log.LogIndex = "0x1"
		}},
		{"conflicting_amount", func(log *rpc.Log) {
			log.Data = fmt.Sprintf("0x%064x", 200)
		}},
		{"conflicting_transaction", func(log *rpc.Log) {
			log.TransactionHash = "0x" + strings.Repeat("f", 64)
		}},
		{"conflicting_transaction_index", func(log *rpc.Log) {
			log.TransactionIndex = "0x1"
		}},
		{"conflicting_recipient", func(log *rpc.Log) {
			log.Topics[2] = "0x" + strings.Repeat("0", 24) + strings.Repeat("3", 40)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first := makeTransferLog(a, b, 100, 0)
			second := makeTransferLog(a, b, 100, 0)
			tt.mutate(&second)
			server := mockRPC([]rpc.Log{first, second})
			defer server.Close()
			var output bytes.Buffer
			err := run(
				context.Background(),
				[]string{"-from-block", "100", "-to-block", "120"},
				server.URL,
				&output,
				io.Discard,
			)
			if err == nil {
				t.Fatal("conflicting RPC data accepted")
			}
			if output.Len() != 0 {
				t.Fatal("report emitted for conflicting RPC data")
			}
		})
	}
}

func TestIdenticalDuplicateLogs(t *testing.T) {
	a := "0x" + strings.Repeat("1", 40)
	b := "0x" + strings.Repeat("2", 40)
	log := makeTransferLog(a, b, 100, 0)
	server := mockRPC([]rpc.Log{log, log})
	defer server.Close()
	var output bytes.Buffer
	err := run(
		context.Background(),
		[]string{"-from-block", "100", "-to-block", "120"},
		server.URL,
		&output,
		io.Discard,
	)
	if err != nil {
		t.Fatal(err)
	}
	var result report.Report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Summary.Transfers != 1 {
		t.Fatal("duplicate transfer affected accounting")
	}
	if result.Summary.DuplicateEvents != 1 {
		t.Fatal("duplicate event count mismatch")
	}
}

func TestDeterministicOutput(t *testing.T) {
	a := "0x" + strings.Repeat("1", 40)
	b := "0x" + strings.Repeat("2", 40)
	server := mockRPC([]rpc.Log{
		makeTransferLog(a, b, 100, 0),
		makeTransferLog(b, a, 101, 0),
	})
	defer server.Close()
	var first bytes.Buffer
	var second bytes.Buffer
	args := []string{"-from-block", "100", "-to-block", "120"}
	if err := run(context.Background(), args, server.URL, &first, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), args, server.URL, &second, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("nondeterministic CLI output")
	}
}
