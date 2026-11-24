package decoder

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"evm-forensics-engine/internal/rpc"
)

const (
	TransferTopic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	ApprovalTopic = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
)

type EventKind string

const (
	Transfer EventKind = "transfer"
	Approval EventKind = "approval"
)

var (
	ErrUnsupportedEvent = errors.New("unsupported event")
	ErrInvalidEvent     = errors.New("invalid event")
)

type Event struct {
	Kind             EventKind `json:"kind"`
	Token            string    `json:"token"`
	From             string    `json:"from"`
	To               string    `json:"to"`
	Amount           string    `json:"amount"`
	BlockNumber      uint64    `json:"block_number"`
	BlockHash        string    `json:"block_hash"`
	TransactionHash  string    `json:"transaction_hash"`
	TransactionIndex uint64    `json:"transaction_index"`
	LogIndex         uint64    `json:"log_index"`
}

func Decode(log rpc.Log) (Event, error) {
	if len(log.Topics) == 0 {
		return Event{}, ErrUnsupportedEvent
	}

	var kind EventKind
	switch strings.ToLower(log.Topics[0]) {
	case TransferTopic:
		kind = Transfer
	case ApprovalTopic:
		kind = Approval
	default:
		return Event{}, ErrUnsupportedEvent
	}

	if len(log.Topics) == 4 && log.Data == "0x" {
		return Event{}, ErrUnsupportedEvent
	}
	if log.Removed {
		return Event{}, fmt.Errorf("%w: removed log", ErrInvalidEvent)
	}
	if len(log.Topics) != 3 {
		return Event{}, fmt.Errorf("%w: topic count", ErrInvalidEvent)
	}
	if !validHex(log.Address, 20) {
		return Event{}, fmt.Errorf("%w: token address", ErrInvalidEvent)
	}
	if !validHex(log.BlockHash, 32) {
		return Event{}, fmt.Errorf("%w: block hash", ErrInvalidEvent)
	}
	if !validHex(log.TransactionHash, 32) {
		return Event{}, fmt.Errorf("%w: transaction hash", ErrInvalidEvent)
	}

	from, err := decodeAddress(log.Topics[1])
	if err != nil {
		return Event{}, err
	}
	to, err := decodeAddress(log.Topics[2])
	if err != nil {
		return Event{}, err
	}
	amount, err := decodeAmount(log.Data)
	if err != nil {
		return Event{}, err
	}
	block, err := decodeQuantity(log.BlockNumber)
	if err != nil {
		return Event{}, err
	}
	txIndex, err := decodeQuantity(log.TransactionIndex)
	if err != nil {
		return Event{}, err
	}
	logIndex, err := decodeQuantity(log.LogIndex)
	if err != nil {
		return Event{}, err
	}

	return Event{
		Kind:             kind,
		Token:            strings.ToLower(log.Address),
		From:             from,
		To:               to,
		Amount:           amount,
		BlockNumber:      block,
		BlockHash:        strings.ToLower(log.BlockHash),
		TransactionHash:  strings.ToLower(log.TransactionHash),
		TransactionIndex: txIndex,
		LogIndex:         logIndex,
	}, nil
}

func decodeAddress(topic string) (string, error) {
	if !validHex(topic, 32) {
		return "", fmt.Errorf("%w: address topic", ErrInvalidEvent)
	}
	if topic[2:26] != strings.Repeat("0", 24) {
		return "", fmt.Errorf("%w: address padding", ErrInvalidEvent)
	}
	return "0x" + strings.ToLower(topic[26:]), nil
}

func decodeAmount(data string) (string, error) {
	if !validHex(data, 32) {
		return "", fmt.Errorf("%w: uint256 data", ErrInvalidEvent)
	}
	raw, err := hex.DecodeString(data[2:])
	if err != nil {
		return "", fmt.Errorf("%w: uint256 encoding", ErrInvalidEvent)
	}
	return new(big.Int).SetBytes(raw).String(), nil
}

func decodeQuantity(value string) (uint64, error) {
	if !strings.HasPrefix(value, "0x") || len(value) < 3 {
		return 0, fmt.Errorf("%w: quantity format", ErrInvalidEvent)
	}
	digits := value[2:]
	if len(digits) > 1 && digits[0] == '0' {
		return 0, fmt.Errorf("%w: quantity encoding", ErrInvalidEvent)
	}
	for _, digit := range digits {
		if !strings.ContainsRune("0123456789abcdefABCDEF", digit) {
			return 0, fmt.Errorf("%w: quantity digit", ErrInvalidEvent)
		}
	}
	result, err := strconv.ParseUint(digits, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: quantity overflow", ErrInvalidEvent)
	}
	return result, nil
}

func validHex(value string, size int) bool {
	if !strings.HasPrefix(value, "0x") || len(value) != 2+size*2 {
		return false
	}
	_, err := hex.DecodeString(value[2:])
	return err == nil
}
