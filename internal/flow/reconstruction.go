package flow

import (
	"errors"
	"fmt"
	"math/big"
	"sort"

	"evm-forensics-engine/internal/decoder"
	"evm-forensics-engine/internal/rpc"
)

const ZeroAddress = "0x0000000000000000000000000000000000000000"

var (
	ErrConflictingEvent        = errors.New("conflicting event")
	ErrInconsistentBlock       = errors.New("inconsistent block")
	ErrInconsistentTransaction = errors.New("inconsistent transaction")
)

type Snapshot struct {
	Transfers         []decoder.Event `json:"transfers"`
	Approvals         []decoder.Event `json:"approvals"`
	Balances          []AddressFlow   `json:"address_flows"`
	DuplicateEvents   int             `json:"duplicate_events"`
	UnsupportedEvents int             `json:"unsupported_events"`
}

type AddressFlow struct {
	Token    string `json:"token"`
	Address  string `json:"address"`
	Incoming string `json:"incoming"`
	Outgoing string `json:"outgoing"`
	Net      string `json:"net"`
	Minted   string `json:"minted"`
	Burned   string `json:"burned"`
}

type eventPosition struct {
	block uint64
	index uint64
}

type transactionPosition struct {
	block uint64
	index uint64
}

type balanceKey struct {
	token   string
	address string
}

type accumulator struct {
	incoming big.Int
	outgoing big.Int
	minted   big.Int
	burned   big.Int
}

func Reconstruct(logs []rpc.Log) (Snapshot, error) {
	result := Snapshot{
		Transfers: make([]decoder.Event, 0),
		Approvals: make([]decoder.Event, 0),
		Balances:  make([]AddressFlow, 0),
	}
	positions := make(map[eventPosition]decoder.Event)
	blocks := make(map[uint64]string)
	transactions := make(map[transactionPosition]string)
	transactionHashes := make(map[string]transactionPosition)
	balances := make(map[balanceKey]*accumulator)

	for _, log := range logs {
		event, err := decoder.Decode(log)
		if errors.Is(err, decoder.ErrUnsupportedEvent) {
			result.UnsupportedEvents++
			continue
		}
		if err != nil {
			return Snapshot{}, fmt.Errorf("decode event: %w", err)
		}
		if hash, exists := blocks[event.BlockNumber]; exists && hash != event.BlockHash {
			return Snapshot{}, fmt.Errorf("%w: %d", ErrInconsistentBlock, event.BlockNumber)
		}
		blocks[event.BlockNumber] = event.BlockHash

		txPosition := transactionPosition{
			block: event.BlockNumber,
			index: event.TransactionIndex,
		}
		if hash, exists := transactions[txPosition]; exists && hash != event.TransactionHash {
			return Snapshot{}, ErrInconsistentTransaction
		}
		if previous, exists := transactionHashes[event.TransactionHash]; exists && previous != txPosition {
			return Snapshot{}, ErrInconsistentTransaction
		}
		transactions[txPosition] = event.TransactionHash
		transactionHashes[event.TransactionHash] = txPosition

		position := eventPosition{
			block: event.BlockNumber,
			index: event.LogIndex,
		}
		if previous, exists := positions[position]; exists {
			if previous != event {
				return Snapshot{}, fmt.Errorf(
					"%w: block %d log %d",
					ErrConflictingEvent,
					event.BlockNumber,
					event.LogIndex,
				)
			}
			result.DuplicateEvents++
			continue
		}
		positions[position] = event

		switch event.Kind {
		case decoder.Transfer:
			result.Transfers = append(result.Transfers, event)
			if err := accumulate(balances, event); err != nil {
				return Snapshot{}, err
			}
		case decoder.Approval:
			result.Approvals = append(result.Approvals, event)
		}
	}

	sortEvents(result.Transfers)
	sortEvents(result.Approvals)

	for key, value := range balances {
		net := new(big.Int).Sub(&value.incoming, &value.outgoing)
		result.Balances = append(result.Balances, AddressFlow{
			Token:    key.token,
			Address:  key.address,
			Incoming: value.incoming.String(),
			Outgoing: value.outgoing.String(),
			Net:      net.String(),
			Minted:   value.minted.String(),
			Burned:   value.burned.String(),
		})
	}

	sort.Slice(result.Balances, func(i, j int) bool {
		a, b := result.Balances[i], result.Balances[j]
		if a.Token != b.Token {
			return a.Token < b.Token
		}
		return a.Address < b.Address
	})

	return result, nil
}

func accumulate(balances map[balanceKey]*accumulator, event decoder.Event) error {
	amount, ok := new(big.Int).SetString(event.Amount, 10)
	if !ok || amount.Sign() < 0 || amount.BitLen() > 256 {
		return errors.New("invalid transfer amount")
	}

	if event.From != ZeroAddress {
		sender := getAccumulator(balances, event.Token, event.From)
		sender.outgoing.Add(&sender.outgoing, amount)
		if event.To == ZeroAddress {
			sender.burned.Add(&sender.burned, amount)
		}
	}

	if event.To != ZeroAddress {
		recipient := getAccumulator(balances, event.Token, event.To)
		recipient.incoming.Add(&recipient.incoming, amount)
		if event.From == ZeroAddress {
			recipient.minted.Add(&recipient.minted, amount)
		}
	}

	return nil
}

func getAccumulator(balances map[balanceKey]*accumulator, token, address string) *accumulator {
	key := balanceKey{
		token:   token,
		address: address,
	}
	value, exists := balances[key]
	if !exists {
		value = &accumulator{}
		balances[key] = value
	}
	return value
}

func sortEvents(events []decoder.Event) {
	sort.Slice(events, func(i, j int) bool {
		a, b := events[i], events[j]
		if a.BlockNumber != b.BlockNumber {
			return a.BlockNumber < b.BlockNumber
		}
		if a.TransactionIndex != b.TransactionIndex {
			return a.TransactionIndex < b.TransactionIndex
		}
		return a.LogIndex < b.LogIndex
	})
}
