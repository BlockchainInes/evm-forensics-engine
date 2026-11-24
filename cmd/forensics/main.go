package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"evm-forensics-engine/internal/decoder"
	"evm-forensics-engine/internal/detection"
	"evm-forensics-engine/internal/flow"
	"evm-forensics-engine/internal/report"
	"evm-forensics-engine/internal/rpc"
)

const (
	maxBlockRange = 1000
	maxLogs       = 100000
)

type options struct {
	fromBlock     uint64
	toBlock       uint64
	token         string
	window        uint64
	minRecipients int
	maxCycleHops  int
	timeout       time.Duration
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Getenv("EVM_RPC_URL"), os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, endpoint string, stdout, stderr io.Writer) error {
	opts, err := parseOptions(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	if endpoint == "" {
		return errors.New("EVM_RPC_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, opts.timeout)
	defer cancel()
	client, err := rpc.NewClient(rpc.Config{
		Endpoint:      endpoint,
		Timeout:       30 * time.Second,
		MaxConcurrent: 4,
		MaxRetries:    3,
		RetryDelay:    500 * time.Millisecond,
	})
	if err != nil {
		return err
	}
	engine, err := detection.NewEngine(detection.Config{
		WindowBlocks:  opts.window,
		MinRecipients: opts.minRecipients,
		MaxCycleHops:  opts.maxCycleHops,
	})
	if err != nil {
		return err
	}
	chainID, err := readChainID(ctx, client)
	if err != nil {
		return err
	}
	logs, err := readLogs(ctx, client, opts)
	if err != nil {
		return err
	}
	snapshot, err := flow.Reconstruct(logs)
	if err != nil {
		return fmt.Errorf("reconstruct flows: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	findings := engine.Analyze(snapshot)
	if err := ctx.Err(); err != nil {
		return err
	}
	result := report.New(
		report.Scope{
			ChainID:       chainID,
			FromBlock:     opts.fromBlock,
			ToBlock:       opts.toBlock,
			TokenFilter:   opts.token,
			WindowBlocks:  opts.window,
			MinRecipients: opts.minRecipients,
			MaxCycleHops:  opts.maxCycleHops,
		},
		snapshot,
		findings,
	)
	return report.WriteJSON(stdout, result)
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	var opts options
	flags := flag.NewFlagSet("forensics", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Uint64Var(&opts.fromBlock, "from-block", 0, "First block")
	flags.Uint64Var(&opts.toBlock, "to-block", 0, "Last block")
	flags.StringVar(&opts.token, "token", "", "ERC-20 contract address")
	flags.Uint64Var(&opts.window, "window", 20, "Detection window in blocks")
	flags.IntVar(&opts.minRecipients, "min-recipients", 5, "Minimum distinct recipients")
	flags.IntVar(&opts.maxCycleHops, "max-cycle-hops", 5, "Maximum cycle length")
	flags.DurationVar(&opts.timeout, "timeout", 2*time.Minute, "Analysis timeout")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, errors.New("unexpected positional arguments")
	}
	provided := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) {
		provided[f.Name] = true
	})
	if !provided["from-block"] || !provided["to-block"] {
		return options{}, errors.New("from-block and to-block are required")
	}
	if opts.fromBlock > opts.toBlock {
		return options{}, errors.New("invalid block range")
	}
	if opts.toBlock-opts.fromBlock >= maxBlockRange {
		return options{}, errors.New("block range exceeds maximum of 1000 blocks")
	}
	if opts.timeout <= 0 || opts.timeout > 10*time.Minute {
		return options{}, errors.New("invalid analysis timeout")
	}
	if opts.token != "" {
		if !validAddress(opts.token) {
			return options{}, errors.New("invalid token address")
		}
		opts.token = strings.ToLower(opts.token)
	}
	_, err := detection.NewEngine(detection.Config{
		WindowBlocks:  opts.window,
		MinRecipients: opts.minRecipients,
		MaxCycleHops:  opts.maxCycleHops,
	})
	if err != nil {
		return options{}, err
	}
	return opts, nil
}

func readChainID(ctx context.Context, client *rpc.Client) (string, error) {
	var raw string
	if err := client.Call(ctx, "eth_chainId", nil, &raw); err != nil {
		return "", fmt.Errorf("read chain ID: %w", err)
	}
	if !strings.HasPrefix(raw, "0x") || len(raw) < 3 || len(raw) > 66 {
		return "", errors.New("invalid chain ID")
	}
	digits := raw[2:]
	if len(digits) > 1 && digits[0] == '0' {
		return "", errors.New("invalid chain ID encoding")
	}
	for _, digit := range digits {
		if !strings.ContainsRune("0123456789abcdefABCDEF", digit) {
			return "", errors.New("invalid chain ID digit")
		}
	}
	value, ok := new(big.Int).SetString(digits, 16)
	if !ok || value.Sign() <= 0 || value.BitLen() > 256 {
		return "", errors.New("invalid chain ID value")
	}
	return value.String(), nil
}

func readLogs(ctx context.Context, client *rpc.Client, opts options) ([]rpc.Log, error) {
	filter := rpc.LogFilter{
		Topics: []any{
			[]string{
				decoder.TransferTopic,
				decoder.ApprovalTopic,
			},
		},
	}
	if opts.token != "" {
		filter.Address = []string{opts.token}
	}
	cfg := rpc.DefaultIngestionConfig()
	cfg.MaxLogs = maxLogs
	logs, err := client.IngestLogs(
		ctx,
		opts.fromBlock,
		opts.toBlock,
		filter,
		cfg,
	)
	if err != nil {
		return nil, fmt.Errorf("ingest event logs: %w", err)
	}
	blockHashes := make(map[uint64]string)
	positions := make(map[[2]uint64]rpc.Log)
	for _, log := range logs {
		if log.Removed {
			return nil, errors.New("removed log received")
		}
		block, err := parseBlockNumber(log.BlockNumber)
		if err != nil {
			return nil, err
		}
		if block < opts.fromBlock || block > opts.toBlock {
			return nil, errors.New("RPC log outside requested block range")
		}
		if opts.token != "" && !strings.EqualFold(log.Address, opts.token) {
			return nil, errors.New("RPC log outside requested token filter")
		}
		if len(log.Topics) == 0 {
			return nil, errors.New("RPC log missing event signature")
		}
		signature := strings.ToLower(log.Topics[0])
		if signature != decoder.TransferTopic && signature != decoder.ApprovalTopic {
			return nil, errors.New("RPC log outside requested event filter")
		}
		blockHash := strings.ToLower(log.BlockHash)
		if previous, exists := blockHashes[block]; exists && previous != blockHash {
			return nil, errors.New("conflicting block hashes")
		}
		blockHashes[block] = blockHash
		index, err := parseBlockNumber(log.LogIndex)
		if err != nil {
			return nil, err
		}
		key := [2]uint64{block, index}
		if previous, exists := positions[key]; exists {
			if !equalLogs(previous, log) {
				return nil, errors.New("conflicting logs at identical event position")
			}
		} else {
			positions[key] = log
		}
	}
	return logs, nil
}

func equalLogs(a, b rpc.Log) bool {
	if !strings.EqualFold(a.Address, b.Address) ||
		!strings.EqualFold(a.BlockHash, b.BlockHash) ||
		!strings.EqualFold(a.TransactionHash, b.TransactionHash) ||
		!strings.EqualFold(a.Data, b.Data) ||
		a.Removed != b.Removed ||
		len(a.Topics) != len(b.Topics) {
		return false
	}
	aIndex, aErr := parseBlockNumber(a.TransactionIndex)
	bIndex, bErr := parseBlockNumber(b.TransactionIndex)
	if aErr != nil || bErr != nil || aIndex != bIndex {
		return false
	}
	for i := range a.Topics {
		if !strings.EqualFold(a.Topics[i], b.Topics[i]) {
			return false
		}
	}
	return true
}

func parseBlockNumber(value string) (uint64, error) {
	if !strings.HasPrefix(value, "0x") || len(value) < 3 {
		return 0, errors.New("invalid block number")
	}
	digits := value[2:]
	if len(digits) > 1 && digits[0] == '0' {
		return 0, errors.New("invalid block number encoding")
	}
	for _, digit := range digits {
		if !strings.ContainsRune("0123456789abcdefABCDEF", digit) {
			return 0, errors.New("invalid block number digit")
		}
	}
	block, err := strconv.ParseUint(digits, 16, 64)
	if err != nil {
		return 0, errors.New("invalid block number value")
	}
	return block, nil
}

func validAddress(value string) bool {
	if len(value) != 42 || !strings.HasPrefix(value, "0x") {
		return false
	}
	_, err := hex.DecodeString(value[2:])
	return err == nil
}
