package flow

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"evm-forensics-engine/internal/decoder"
	"evm-forensics-engine/internal/rpc"
)

var (
	tokenA   = "0x" + strings.Repeat("a", 40)
	tokenB   = "0x" + strings.Repeat("f", 40)
	addressA = "0x" + strings.Repeat("b", 40)
	addressB = "0x" + strings.Repeat("c", 40)
	addressC = "0x" + strings.Repeat("d", 40)
)

func makeLog(token, from, to string, amount, block, index uint64) rpc.Log {
	return rpc.Log{
		Address: token,
		Topics: []string{
			decoder.TransferTopic,
			"0x" + strings.Repeat("0", 24) + from[2:],
			"0x" + strings.Repeat("0", 24) + to[2:],
		},
		Data:             fmt.Sprintf("0x%064x", amount),
		BlockNumber:      fmt.Sprintf("0x%x", block),
		BlockHash:        fmt.Sprintf("0x%064x", block),
		TransactionHash:  fmt.Sprintf("0x%032x%032x", block, index),
		TransactionIndex: fmt.Sprintf("0x%x", index),
		LogIndex:         fmt.Sprintf("0x%x", index),
	}
}

func findFlow(t *testing.T, snapshot Snapshot, token, address string) AddressFlow {
	t.Helper()
	for _, value := range snapshot.Balances {
		if value.Token == token && value.Address == address {
			return value
		}
	}
	t.Fatalf("missing address flow: %s %s", token, address)
	return AddressFlow{}
}

func TestReconstructTransfers(t *testing.T) {
	logs := []rpc.Log{
		makeLog(tokenA, addressA, addressB, 100, 10, 0),
		makeLog(tokenA, addressB, addressC, 40, 11, 0),
	}
	snapshot, err := Reconstruct(logs)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Transfers) != 2 || len(snapshot.Balances) != 3 {
		t.Fatal("unexpected reconstruction size")
	}

	a := findFlow(t, snapshot, tokenA, addressA)
	b := findFlow(t, snapshot, tokenA, addressB)
	c := findFlow(t, snapshot, tokenA, addressC)

	if a.Incoming != "0" || a.Outgoing != "100" || a.Net != "-100" {
		t.Fatalf("unexpected sender flow: %+v", a)
	}
	if b.Incoming != "100" || b.Outgoing != "40" || b.Net != "60" {
		t.Fatalf("unexpected intermediary flow: %+v", b)
	}
	if c.Incoming != "40" || c.Net != "40" {
		t.Fatalf("unexpected recipient flow: %+v", c)
	}
}

func TestDeterministicReconstruction(t *testing.T) {
	first := makeLog(tokenA, addressA, addressB, 100, 10, 0)
	second := makeLog(tokenA, addressB, addressC, 40, 11, 0)
	third := makeLog(tokenA, addressC, addressA, 10, 12, 0)

	a, err := Reconstruct([]rpc.Log{first, second, third})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Reconstruct([]rpc.Log{third, first, second})
	if err != nil {
		t.Fatal(err)
	}

	left, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	right, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(left) != string(right) {
		t.Fatal("nondeterministic reconstruction")
	}
}

func TestDuplicateEvents(t *testing.T) {
	log := makeLog(tokenA, addressA, addressB, 100, 10, 0)
	snapshot, err := Reconstruct([]rpc.Log{log, log, log})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Transfers) != 1 || snapshot.DuplicateEvents != 2 {
		t.Fatal("duplicate event accounting failed")
	}
	value := findFlow(t, snapshot, tokenA, addressB)
	if value.Incoming != "100" {
		t.Fatal("duplicate transfer affected aggregation")
	}
}

func TestConflictingEvents(t *testing.T) {
	first := makeLog(tokenA, addressA, addressB, 100, 10, 0)
	second := makeLog(tokenA, addressA, addressB, 200, 10, 0)

	_, err := Reconstruct([]rpc.Log{first, second})
	if !errors.Is(err, ErrConflictingEvent) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInconsistentBlock(t *testing.T) {
	first := makeLog(tokenA, addressA, addressB, 100, 10, 0)
	second := makeLog(tokenA, addressB, addressC, 50, 10, 1)
	second.BlockHash = "0x" + strings.Repeat("f", 64)

	_, err := Reconstruct([]rpc.Log{first, second})
	if !errors.Is(err, ErrInconsistentBlock) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInconsistentTransaction(t *testing.T) {
	first := makeLog(tokenA, addressA, addressB, 100, 10, 0)
	second := makeLog(tokenA, addressB, addressC, 50, 10, 1)
	second.TransactionIndex = first.TransactionIndex

	_, err := Reconstruct([]rpc.Log{first, second})
	if !errors.Is(err, ErrInconsistentTransaction) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTransactionHashPositionConflict(t *testing.T) {
	first := makeLog(tokenA, addressA, addressB, 100, 10, 0)
	second := makeLog(tokenA, addressB, addressC, 50, 11, 0)
	second.TransactionHash = first.TransactionHash

	_, err := Reconstruct([]rpc.Log{first, second})
	if !errors.Is(err, ErrInconsistentTransaction) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMintAndBurn(t *testing.T) {
	logs := []rpc.Log{
		makeLog(tokenA, ZeroAddress, addressA, 1000, 10, 0),
		makeLog(tokenA, addressA, ZeroAddress, 250, 11, 0),
	}
	snapshot, err := Reconstruct(logs)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Balances) != 1 {
		t.Fatal("unexpected zero-address aggregation")
	}
	value := findFlow(t, snapshot, tokenA, addressA)
	if value.Minted != "1000" ||
		value.Burned != "250" ||
		value.Incoming != "1000" ||
		value.Outgoing != "250" ||
		value.Net != "750" {
		t.Fatalf("unexpected mint/burn flow: %+v", value)
	}
}

func TestApprovalIsolation(t *testing.T) {
	approval := makeLog(tokenA, addressA, addressB, 1000, 10, 0)
	approval.Topics[0] = decoder.ApprovalTopic

	snapshot, err := Reconstruct([]rpc.Log{approval})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Approvals) != 1 ||
		len(snapshot.Transfers) != 0 ||
		len(snapshot.Balances) != 0 {
		t.Fatal("approval affected transfer accounting")
	}
}

func TestTokenIsolation(t *testing.T) {
	logs := []rpc.Log{
		makeLog(tokenA, addressA, addressB, 100, 10, 0),
		makeLog(tokenB, addressA, addressB, 200, 10, 1),
	}
	snapshot, err := Reconstruct(logs)
	if err != nil {
		t.Fatal(err)
	}
	a := findFlow(t, snapshot, tokenA, addressB)
	b := findFlow(t, snapshot, tokenB, addressB)
	if a.Incoming != "100" || b.Incoming != "200" {
		t.Fatal("cross-token accounting contamination")
	}
}

func TestSelfTransfer(t *testing.T) {
	log := makeLog(tokenA, addressA, addressA, 100, 10, 0)
	snapshot, err := Reconstruct([]rpc.Log{log})
	if err != nil {
		t.Fatal(err)
	}
	value := findFlow(t, snapshot, tokenA, addressA)
	if value.Incoming != "100" ||
		value.Outgoing != "100" ||
		value.Net != "0" {
		t.Fatal("self-transfer accounting failed")
	}
}

func TestLargeAmountAggregation(t *testing.T) {
	first := makeLog(tokenA, addressA, addressB, 0, 10, 0)
	second := makeLog(tokenA, addressA, addressB, 0, 11, 0)

	first.Data = "0x" + strings.Repeat("f", 64)
	second.Data = first.Data

	snapshot, err := Reconstruct([]rpc.Log{first, second})
	if err != nil {
		t.Fatal(err)
	}
	maximum := new(big.Int).Lsh(big.NewInt(1), 256)
	maximum.Sub(maximum, big.NewInt(1))
	expected := new(big.Int).Mul(maximum, big.NewInt(2))

	value := findFlow(t, snapshot, tokenA, addressB)
	if value.Incoming != expected.String() {
		t.Fatal("large amount aggregation failed")
	}
}

func TestInvalidEventRejected(t *testing.T) {
	log := makeLog(tokenA, addressA, addressB, 100, 10, 0)
	log.Data = "0x01"

	_, err := Reconstruct([]rpc.Log{log})
	if !errors.Is(err, decoder.ErrInvalidEvent) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUnsupportedEventAccounting(t *testing.T) {
	log := makeLog(tokenA, addressA, addressB, 100, 10, 0)
	log.Topics[0] = "0x" + strings.Repeat("1", 64)

	snapshot, err := Reconstruct([]rpc.Log{log})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.UnsupportedEvents != 1 ||
		len(snapshot.Transfers) != 0 {
		t.Fatal("unsupported event accounting failed")
	}
}

func TestEmptySnapshot(t *testing.T) {
	snapshot, err := Reconstruct(nil)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Transfers == nil ||
		snapshot.Approvals == nil ||
		snapshot.Balances == nil {
		t.Fatal("unexpected null collection")
	}
}

func BenchmarkReconstruct1000(b *testing.B) {
	logs := make([]rpc.Log, 1000)
	for i := range logs {
		logs[i] = makeLog(
			tokenA,
			addressA,
			addressB,
			100,
			10,
			uint64(i),
		)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Reconstruct(logs); err != nil {
			b.Fatal(err)
		}
	}
}
