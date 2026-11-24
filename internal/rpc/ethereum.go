package rpc

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func (c *Client) ChainID(ctx context.Context) (uint64, error) {
	var result string
	if err := c.Call(ctx, "eth_chainId", nil, &result); err != nil {
		return 0, err
	}
	return parseQuantity(result)
}

func (c *Client) BlockNumber(ctx context.Context) (uint64, error) {
	var result string
	if err := c.Call(ctx, "eth_blockNumber", nil, &result); err != nil {
		return 0, err
	}
	return parseQuantity(result)
}

func (c *Client) TransactionByHash(ctx context.Context, hash string) (*Transaction, error) {
	if !validHex(hash, 32) {
		return nil, errors.New("invalid transaction hash")
	}
	var result *Transaction
	if err := c.Call(ctx, "eth_getTransactionByHash", []any{hash}, &result); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("transaction not found")
	}
	if !strings.EqualFold(result.Hash, hash) {
		return nil, errors.New("transaction hash mismatch")
	}
	return result, nil
}

func (c *Client) TransactionReceipt(ctx context.Context, hash string) (*Receipt, error) {
	if !validHex(hash, 32) {
		return nil, errors.New("invalid transaction hash")
	}
	var result *Receipt
	if err := c.Call(ctx, "eth_getTransactionReceipt", []any{hash}, &result); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("transaction receipt not found")
	}
	if !strings.EqualFold(result.TransactionHash, hash) {
		return nil, errors.New("receipt transaction hash mismatch")
	}
	return result, nil
}

func (c *Client) BlockByNumber(ctx context.Context, number uint64) (*Block, error) {
	var result *Block
	if err := c.Call(ctx, "eth_getBlockByNumber", []any{formatQuantity(number), false}, &result); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("block not found")
	}
	actual, err := parseQuantity(result.Number)
	if err != nil || actual != number {
		return nil, errors.New("block number mismatch")
	}
	if !validHex(result.Hash, 32) || !validHex(result.ParentHash, 32) {
		return nil, errors.New("invalid block hash")
	}
	return result, nil
}

func (c *Client) FinalizedBlock(ctx context.Context) (*Block, error) {
	var result *Block
	if err := c.Call(ctx, "eth_getBlockByNumber", []any{"finalized", false}, &result); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("finalized block unavailable")
	}
	if _, err := parseQuantity(result.Number); err != nil {
		return nil, err
	}
	if !validHex(result.Hash, 32) || !validHex(result.ParentHash, 32) {
		return nil, errors.New("invalid finalized block hash")
	}
	return result, nil
}

func (c *Client) Logs(ctx context.Context, filter LogFilter) ([]Log, error) {
	if filter.BlockHash != "" {
		if !validHex(filter.BlockHash, 32) || filter.FromBlock != "" || filter.ToBlock != "" {
			return nil, errors.New("invalid block hash filter")
		}
	} else {
		from, err := parseQuantity(filter.FromBlock)
		if err != nil {
			return nil, fmt.Errorf("invalid fromBlock: %w", err)
		}
		to, err := parseQuantity(filter.ToBlock)
		if err != nil {
			return nil, fmt.Errorf("invalid toBlock: %w", err)
		}
		if from > to {
			return nil, errors.New("invalid block range")
		}
	}
	for _, address := range filter.Address {
		if !validHex(address, 20) {
			return nil, errors.New("invalid filter address")
		}
	}
	var result []Log
	if err := c.Call(ctx, "eth_getLogs", []any{filter}, &result); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("invalid null log result")
	}
	return result, nil
}

func parseQuantity(value string) (uint64, error) {
	if !strings.HasPrefix(value, "0x") || len(value) < 3 {
		return 0, errors.New("invalid hexadecimal quantity")
	}
	digits := value[2:]
	if len(digits) > 1 && digits[0] == '0' {
		return 0, errors.New("noncanonical hexadecimal quantity")
	}
	for _, digit := range digits {
		if !strings.ContainsRune("0123456789abcdefABCDEF", digit) {
			return 0, errors.New("invalid hexadecimal digit")
		}
	}
	return strconv.ParseUint(digits, 16, 64)
}

func formatQuantity(value uint64) string {
	return "0x" + strconv.FormatUint(value, 16)
}

func validHex(value string, size int) bool {
	if !strings.HasPrefix(value, "0x") || len(value) != 2+size*2 {
		return false
	}
	_, err := hex.DecodeString(value[2:])
	return err == nil
}
