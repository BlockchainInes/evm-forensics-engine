package rpc

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

type IngestionConfig struct {
	Workers           int
	ChunkSize         uint64
	RequestsPerSecond int
	MaxLogs           int
}

type blockRange struct {
	from uint64
	to   uint64
}

type ingestionResult struct {
	logs []Log
	err  error
}

func DefaultIngestionConfig() IngestionConfig {
	return IngestionConfig{
		Workers:           4,
		ChunkSize:         100,
		RequestsPerSecond: 5,
		MaxLogs:           100000,
	}
}

func (c *Client) IngestLogs(
	ctx context.Context,
	from, to uint64,
	filter LogFilter,
	cfg IngestionConfig,
) ([]Log, error) {
	if from > to || to-from >= 1000 {
		return nil, errors.New("invalid ingestion block range")
	}
	if cfg.Workers < 1 || cfg.Workers > 32 ||
		cfg.ChunkSize < 1 || cfg.ChunkSize > 1000 ||
		cfg.RequestsPerSecond < 1 || cfg.RequestsPerSecond > 100 ||
		cfg.MaxLogs < 1 || cfg.MaxLogs > 100000 {
		return nil, errors.New("invalid ingestion configuration")
	}
	if filter.BlockHash != "" ||
		filter.FromBlock != "" ||
		filter.ToBlock != "" {
		return nil, errors.New("conflicting ingestion filter")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan blockRange)
	results := make(chan ingestionResult)
	ticker := time.NewTicker(time.Second / time.Duration(cfg.RequestsPerSecond))
	defer ticker.Stop()

	var workers sync.WaitGroup

	for i := 0; i < cfg.Workers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-jobs:
					if !ok {
						return
					}
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
					}

					request := filter
					request.FromBlock = formatQuantity(job.from)
					request.ToBlock = formatQuantity(job.to)

					logs, err := c.Logs(ctx, request)
					if err == nil {
						err = validateChunk(logs, job)
					}

					select {
					case results <- ingestionResult{logs: logs, err: err}:
					case <-ctx.Done():
						return
					}
					if err != nil {
						return
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for start := from; ; {
			end := to
			if to-start >= cfg.ChunkSize {
				end = start + cfg.ChunkSize - 1
			}
			select {
			case jobs <- blockRange{from: start, to: end}:
			case <-ctx.Done():
				return
			}
			if end == to {
				return
			}
			start = end + 1
		}
	}()

	go func() {
		workers.Wait()
		close(results)
	}()

	all := make([]Log, 0)
	var firstErr error

	for result := range results {
		if firstErr != nil {
			continue
		}
		if result.err != nil {
			firstErr = result.err
			cancel()
			continue
		}
		if len(result.logs) > cfg.MaxLogs-len(all) {
			firstErr = errors.New("ingestion log limit exceeded")
			cancel()
			continue
		}
		all = append(all, result.logs...)
	}

	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	sort.Slice(all, func(i, j int) bool {
		a, b := all[i], all[j]
		ab, _ := parseQuantity(a.BlockNumber)
		bb, _ := parseQuantity(b.BlockNumber)
		if ab != bb {
			return ab < bb
		}
		at, _ := parseQuantity(a.TransactionIndex)
		bt, _ := parseQuantity(b.TransactionIndex)
		if at != bt {
			return at < bt
		}
		al, _ := parseQuantity(a.LogIndex)
		bl, _ := parseQuantity(b.LogIndex)
		return al < bl
	})

	return all, nil
}

func validateChunk(logs []Log, job blockRange) error {
	if logs == nil {
		return errors.New("null ingestion result")
	}
	for _, log := range logs {
		if log.Removed {
			return errors.New("removed log received")
		}
		block, err := parseQuantity(log.BlockNumber)
		if err != nil {
			return fmt.Errorf("invalid log block: %w", err)
		}
		if block < job.from || block > job.to {
			return errors.New("log outside ingestion chunk")
		}
		if _, err := parseQuantity(log.TransactionIndex); err != nil {
			return fmt.Errorf("invalid transaction index: %w", err)
		}
		if _, err := parseQuantity(log.LogIndex); err != nil {
			return fmt.Errorf("invalid log index: %w", err)
		}
	}
	return nil
}
