package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func ingestionTestClient(t *testing.T, endpoint string) *Client {
	t.Helper()
	client, err := NewClient(Config{
		Endpoint:      endpoint,
		Timeout:       5 * time.Second,
		MaxConcurrent: 4,
		MaxRetries:    0,
		RetryDelay:    time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func ingestionTestConfig() IngestionConfig {
	return IngestionConfig{
		Workers:           4,
		ChunkSize:         10,
		RequestsPerSecond: 100,
		MaxLogs:           1000,
	}
}

func ingestionTestLog(block uint64) Log {
	return Log{
		Address:          fmt.Sprintf("0x%040x", 1),
		Topics:           []string{fmt.Sprintf("0x%064x", 1)},
		Data:             "0x",
		BlockNumber:      formatQuantity(block),
		BlockHash:        fmt.Sprintf("0x%064x", block),
		TransactionHash:  fmt.Sprintf("0x%064x", block+1000),
		TransactionIndex: "0x0",
		LogIndex:         "0x0",
	}
}

func ingestionServer(
	handler func(context.Context, LogFilter) ([]Log, int),
) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     uint64      `json:"id"`
			Method string      `json:"method"`
			Params []LogFilter `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if request.Method != "eth_getLogs" || len(request.Params) != 1 {
			http.Error(w, "invalid method", http.StatusBadRequest)
			return
		}

		logs, status := handler(r.Context(), request.Params[0])
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      request.ID,
			"result":  logs,
		})
	}))
}

func TestIngestionChunkCoverage(t *testing.T) {
	var mu sync.Mutex
	covered := make(map[uint64]int)

	server := ingestionServer(func(ctx context.Context, filter LogFilter) ([]Log, int) {
		from, err := parseQuantity(filter.FromBlock)
		if err != nil {
			return nil, http.StatusBadRequest
		}
		to, err := parseQuantity(filter.ToBlock)
		if err != nil {
			return nil, http.StatusBadRequest
		}

		mu.Lock()
		for block := from; block <= to; block++ {
			covered[block]++
		}
		mu.Unlock()

		return []Log{ingestionTestLog(from)}, http.StatusOK
	})
	defer server.Close()

	client := ingestionTestClient(t, server.URL)
	logs, err := client.IngestLogs(
		context.Background(),
		100,
		134,
		LogFilter{},
		ingestionTestConfig(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 4 {
		t.Fatalf("unexpected log count: %d", len(logs))
	}

	mu.Lock()
	defer mu.Unlock()

	if len(covered) != 35 {
		t.Fatal("incomplete block coverage")
	}
	for block := uint64(100); block <= 134; block++ {
		if covered[block] != 1 {
			t.Fatalf("invalid coverage for block %d", block)
		}
	}
	for i, log := range logs {
		want := uint64(100 + i*10)
		if log.BlockNumber != formatQuantity(want) {
			t.Fatal("nondeterministic log ordering")
		}
	}
}

func TestIngestionBoundedConcurrency(t *testing.T) {
	var active atomic.Int64
	var peak atomic.Int64

	server := ingestionServer(func(ctx context.Context, filter LogFilter) ([]Log, int) {
		current := active.Add(1)
		defer active.Add(-1)

		for {
			previous := peak.Load()
			if current <= previous || peak.CompareAndSwap(previous, current) {
				break
			}
		}

		timer := time.NewTimer(100 * time.Millisecond)
		defer timer.Stop()

		select {
		case <-ctx.Done():
			return nil, http.StatusServiceUnavailable
		case <-timer.C:
			return []Log{}, http.StatusOK
		}
	})
	defer server.Close()

	client := ingestionTestClient(t, server.URL)
	cfg := ingestionTestConfig()
	cfg.Workers = 3

	_, err := client.IngestLogs(
		context.Background(),
		100,
		199,
		LogFilter{},
		cfg,
	)
	if err != nil {
		t.Fatal(err)
	}
	if peak.Load() < 2 || peak.Load() > 3 {
		t.Fatalf("unexpected concurrency: %d", peak.Load())
	}
}

func TestIngestionRateLimit(t *testing.T) {
	var requests atomic.Int64

	server := ingestionServer(func(ctx context.Context, filter LogFilter) ([]Log, int) {
		requests.Add(1)
		return []Log{}, http.StatusOK
	})
	defer server.Close()

	client := ingestionTestClient(t, server.URL)
	cfg := ingestionTestConfig()
	cfg.RequestsPerSecond = 10

	start := time.Now()

	_, err := client.IngestLogs(
		context.Background(),
		100,
		139,
		LogFilter{},
		cfg,
	)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 4 {
		t.Fatal("unexpected request count")
	}
	if time.Since(start) < 350*time.Millisecond {
		t.Fatal("request pacing violated")
	}
}

func TestIngestionCancellation(t *testing.T) {
	server := ingestionServer(func(ctx context.Context, filter LogFilter) ([]Log, int) {
		select {
		case <-ctx.Done():
			return nil, http.StatusServiceUnavailable
		case <-time.After(2 * time.Second):
			return []Log{}, http.StatusOK
		}
	})
	defer server.Close()

	client := ingestionTestClient(t, server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	logs, err := client.IngestLogs(
		ctx,
		100,
		199,
		LogFilter{},
		ingestionTestConfig(),
	)
	if err == nil || logs != nil {
		t.Fatal("cancelled ingestion returned a result")
	}
}

func TestIngestionRPCFailure(t *testing.T) {
	server := ingestionServer(func(ctx context.Context, filter LogFilter) ([]Log, int) {
		return nil, http.StatusBadRequest
	})
	defer server.Close()

	client := ingestionTestClient(t, server.URL)

	logs, err := client.IngestLogs(
		context.Background(),
		100,
		199,
		LogFilter{},
		ingestionTestConfig(),
	)
	if err == nil || logs != nil {
		t.Fatal("RPC failure returned partial results")
	}
}

func TestIngestionOutOfRange(t *testing.T) {
	server := ingestionServer(func(ctx context.Context, filter LogFilter) ([]Log, int) {
		return []Log{ingestionTestLog(999)}, http.StatusOK
	})
	defer server.Close()

	client := ingestionTestClient(t, server.URL)

	logs, err := client.IngestLogs(
		context.Background(),
		100,
		109,
		LogFilter{},
		ingestionTestConfig(),
	)
	if err == nil || logs != nil {
		t.Fatal("out-of-range log accepted")
	}
}

func TestIngestionLogLimit(t *testing.T) {
	server := ingestionServer(func(ctx context.Context, filter LogFilter) ([]Log, int) {
		from, _ := parseQuantity(filter.FromBlock)
		return []Log{ingestionTestLog(from)}, http.StatusOK
	})
	defer server.Close()

	client := ingestionTestClient(t, server.URL)
	cfg := ingestionTestConfig()
	cfg.MaxLogs = 2

	logs, err := client.IngestLogs(
		context.Background(),
		100,
		139,
		LogFilter{},
		cfg,
	)
	if err == nil || logs != nil {
		t.Fatal("log limit violation accepted")
	}
}

func TestIngestionInvalidConfig(t *testing.T) {
	client := ingestionTestClient(t, "http://127.0.0.1:1")

	tests := []IngestionConfig{
		{0, 10, 10, 100},
		{33, 10, 10, 100},
		{4, 0, 10, 100},
		{4, 1001, 10, 100},
		{4, 10, 0, 100},
		{4, 10, 101, 100},
		{4, 10, 10, 0},
		{4, 10, 10, 100001},
	}

	for _, cfg := range tests {
		if _, err := client.IngestLogs(
			context.Background(),
			100,
			120,
			LogFilter{},
			cfg,
		); err == nil {
			t.Fatalf("invalid configuration accepted: %+v", cfg)
		}
	}
}
