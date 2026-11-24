package decoder

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"evm-forensics-engine/internal/rpc"
)

func validLog() rpc.Log {
	return rpc.Log{
		Address: "0x" + strings.Repeat("a", 40),
		Topics: []string{
			TransferTopic,
			"0x" + strings.Repeat("0", 24) + strings.Repeat("b", 40),
			"0x" + strings.Repeat("0", 24) + strings.Repeat("c", 40),
		},
		Data:             "0x" + strings.Repeat("0", 62) + "64",
		BlockNumber:      "0x100",
		BlockHash:        "0x" + strings.Repeat("d", 64),
		TransactionHash:  "0x" + strings.Repeat("e", 64),
		TransactionIndex: "0x2",
		LogIndex:         "0x3",
	}
}

func TestDecodeTransfer(t *testing.T) {
	event, err := Decode(validLog())
	if err != nil {
		t.Fatal(err)
	}
	if event.Kind != Transfer {
		t.Fatalf("unexpected event kind: %s", event.Kind)
	}
	if event.Amount != "100" {
		t.Fatalf("unexpected amount: %s", event.Amount)
	}
	if event.Token != "0x"+strings.Repeat("a", 40) {
		t.Fatal("token address mismatch")
	}
	if event.From != "0x"+strings.Repeat("b", 40) {
		t.Fatal("sender address mismatch")
	}
	if event.To != "0x"+strings.Repeat("c", 40) {
		t.Fatal("recipient address mismatch")
	}
	if event.BlockNumber != 256 ||
		event.TransactionIndex != 2 ||
		event.LogIndex != 3 {
		t.Fatal("event position mismatch")
	}
}

func TestDecodeApproval(t *testing.T) {
	log := validLog()
	log.Topics[0] = ApprovalTopic
	event, err := Decode(log)
	if err != nil {
		t.Fatal(err)
	}
	if event.Kind != Approval || event.Amount != "100" {
		t.Fatalf("unexpected approval: %+v", event)
	}
}

func TestDecodeMaxUint256(t *testing.T) {
	log := validLog()
	log.Data = "0x" + strings.Repeat("f", 64)
	event, err := Decode(log)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
	if event.Amount != expected {
		t.Fatalf("uint256 mismatch: %s", event.Amount)
	}
}

func TestDecodeZeroAmount(t *testing.T) {
	log := validLog()
	log.Data = "0x" + strings.Repeat("0", 64)
	event, err := Decode(log)
	if err != nil {
		t.Fatal(err)
	}
	if event.Amount != "0" {
		t.Fatalf("unexpected amount: %s", event.Amount)
	}
}

func TestAddressNormalization(t *testing.T) {
	log := validLog()
	log.Address = "0x" + strings.Repeat("A", 40)
	log.Topics[1] = "0x" + strings.Repeat("0", 24) + strings.Repeat("B", 40)
	event, err := Decode(log)
	if err != nil {
		t.Fatal(err)
	}
	if event.Token != "0x"+strings.Repeat("a", 40) ||
		event.From != "0x"+strings.Repeat("b", 40) {
		t.Fatal("address normalization failed")
	}
}

func TestUnsupportedEvents(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*rpc.Log)
	}{
		{"empty_topics", func(l *rpc.Log) {
			l.Topics = nil
		}},
		{"unknown_signature", func(l *rpc.Log) {
			l.Topics[0] = "0x" + strings.Repeat("1", 64)
		}},
		{"erc721_transfer", func(l *rpc.Log) {
			l.Topics = append(l.Topics, "0x"+strings.Repeat("0", 64))
			l.Data = "0x"
		}},
		{"erc721_approval", func(l *rpc.Log) {
			l.Topics[0] = ApprovalTopic
			l.Topics = append(l.Topics, "0x"+strings.Repeat("0", 64))
			l.Data = "0x"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := validLog()
			tt.mutate(&log)
			if _, err := Decode(log); !errors.Is(err, ErrUnsupportedEvent) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestInvalidEvents(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*rpc.Log)
	}{
		{"removed_log", func(l *rpc.Log) {
			l.Removed = true
		}},
		{"invalid_token", func(l *rpc.Log) {
			l.Address = "0x1234"
		}},
		{"missing_topic", func(l *rpc.Log) {
			l.Topics = l.Topics[:2]
		}},
		{"invalid_address_padding", func(l *rpc.Log) {
			l.Topics[1] = "0x" + strings.Repeat("f", 64)
		}},
		{"invalid_address_topic", func(l *rpc.Log) {
			l.Topics[2] = "0x12"
		}},
		{"short_amount", func(l *rpc.Log) {
			l.Data = "0x01"
		}},
		{"oversized_amount", func(l *rpc.Log) {
			l.Data = "0x" + strings.Repeat("f", 66)
		}},
		{"invalid_amount_hex", func(l *rpc.Log) {
			l.Data = "0x" + strings.Repeat("z", 64)
		}},
		{"invalid_block_hash", func(l *rpc.Log) {
			l.BlockHash = ""
		}},
		{"invalid_transaction_hash", func(l *rpc.Log) {
			l.TransactionHash = "0x1234"
		}},
		{"invalid_block_number", func(l *rpc.Log) {
			l.BlockNumber = "0x00"
		}},
		{"invalid_transaction_index", func(l *rpc.Log) {
			l.TransactionIndex = "0x-1"
		}},
		{"invalid_log_index", func(l *rpc.Log) {
			l.LogIndex = "0xzz"
		}},
		{"quantity_overflow", func(l *rpc.Log) {
			l.BlockNumber = "0x10000000000000000"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := validLog()
			tt.mutate(&log)
			if _, err := Decode(log); !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func FuzzDecodeEvent(f *testing.F) {
	log := validLog()
	f.Add(log.Topics[0], log.Topics[1], log.Topics[2], log.Data, log.BlockNumber)
	f.Add(ApprovalTopic, log.Topics[1], log.Topics[2], log.Data, "0x0")
	f.Add("", "", "", "", "")
	f.Add(TransferTopic, "0x12", "0x34", "0xff", "0xzz")

	f.Fuzz(func(t *testing.T, signature, from, to, data, block string) {
		log := validLog()
		log.Topics = []string{signature, from, to}
		log.Data = data
		log.BlockNumber = block

		event, err := Decode(log)
		if err != nil {
			return
		}
		if event.Kind != Transfer && event.Kind != Approval {
			t.Fatal("invalid decoded event kind")
		}
		if !validHex(event.From, 20) || !validHex(event.To, 20) {
			t.Fatal("invalid decoded address")
		}
		amount, ok := new(big.Int).SetString(event.Amount, 10)
		if !ok || amount.Sign() < 0 || amount.BitLen() > 256 {
			t.Fatal("invalid decoded uint256")
		}
		if amount.String() != event.Amount {
			t.Fatal("noncanonical amount")
		}
	})
}

func BenchmarkDecodeTransfer(b *testing.B) {
	log := validLog()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Decode(log); err != nil {
			b.Fatal(err)
		}
	}
}
