package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := NewClient(Config{
		Endpoint:      server.URL,
		Timeout:       2 * time.Second,
		MaxConcurrent: 4,
		MaxRetries:    2,
		RetryDelay:    time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestChainID(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.Method != "eth_chainId" {
			t.Errorf("unexpected method: %s", req.Method)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result":  "0x1",
		})
	})
	id, err := client.ChainID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id != 1 {
		t.Fatalf("unexpected chain ID: %d", id)
	}
}

func TestRetryOnRateLimit(t *testing.T) {
	var attempts atomic.Int32
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result":  "0x10",
		})
	})
	number, err := client.BlockNumber(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if number != 16 || attempts.Load() != 3 {
		t.Fatalf("unexpected retry result: %d, %d", number, attempts.Load())
	}
}

func TestResponseValidation(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"malformed", `{"jsonrpc":`},
		{"wrong_id", `{"jsonrpc":"2.0","id":999,"result":"0x1"}`},
		{"wrong_version", `{"jsonrpc":"1.0","id":1,"result":"0x1"}`},
		{"missing_result", `{"jsonrpc":"2.0","id":1}`},
		{"conflicting_fields", `{"jsonrpc":"2.0","id":1,"result":"0x1","error":{"code":-32603,"message":"failure"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tt.body))
			})
			if _, err := client.ChainID(context.Background()); err == nil {
				t.Fatal("expected response validation error")
			}
		})
	}
}

func TestRPCErrors(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`))
	})
	_, err := client.ChainID(context.Background())
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) || rpcErr.Code != -32601 {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.ChainID(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected cancellation error: %v", err)
	}
}

func TestInvalidTransactionHash(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("unexpected RPC request")
		w.WriteHeader(http.StatusBadRequest)
	})
	if _, err := client.TransactionByHash(context.Background(), "0x1234"); err == nil {
		t.Fatal("expected invalid hash error")
	}
}

func TestParseQuantity(t *testing.T) {
	tests := []struct {
		input string
		value uint64
		valid bool
	}{
		{"0x0", 0, true},
		{"0x1", 1, true},
		{"0xff", 255, true},
		{"0xffffffffffffffff", ^uint64(0), true},
		{"0x10000000000000000", 0, false},
		{"0x00", 0, false},
		{"0x", 0, false},
		{"0x+1", 0, false},
		{"0x-1", 0, false},
		{"0xzz", 0, false},
		{"", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			value, err := parseQuantity(tt.input)
			if tt.valid {
				if err != nil || value != tt.value {
					t.Fatalf("unexpected result: %d, %v", value, err)
				}
			} else if err == nil {
				t.Fatal("expected invalid quantity error")
			}
		})
	}
}

func TestResponseSizeLimit(t *testing.T) {
	var attempts atomic.Int32
	payload := strings.Repeat("x", maxResponseSize+1)
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	})
	client.httpClient.Timeout = 10 * time.Second
	_, err := client.ChainID(context.Background())
	if err == nil || err.Error() != "RPC response size exceeded" {
		t.Fatalf("unexpected response size error: %v", err)
	}
	if attempts.Load() != 1 {
		t.Fatalf("oversized response retried: %d", attempts.Load())
	}
}

func TestRedirectRejection(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	for _, status := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL, status)
			})
			_, err := client.ChainID(context.Background())
			if err == nil {
				t.Fatal("redirect response accepted")
			}
			if redirected.Load() != 0 {
				t.Fatal("RPC redirect followed")
			}
		})
	}
}

func TestRetryExhaustion(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		attempts int32
	}{
		{"rate_limit", http.StatusTooManyRequests, 3},
		{"bad_gateway", http.StatusBadGateway, 3},
		{"unavailable", http.StatusServiceUnavailable, 3},
		{"gateway_timeout", http.StatusGatewayTimeout, 3},
		{"bad_request", http.StatusBadRequest, 1},
		{"unauthorized", http.StatusUnauthorized, 1},
		{"forbidden", http.StatusForbidden, 1},
		{"internal_error", http.StatusInternalServerError, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var attempts atomic.Int32
			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				w.WriteHeader(tt.status)
			})
			_, err := client.ChainID(context.Background())
			if err == nil {
				t.Fatal("HTTP failure accepted")
			}
			if attempts.Load() != tt.attempts {
				t.Fatalf("unexpected attempt count: %d, expected %d", attempts.Load(), tt.attempts)
			}
		})
	}
}

func TestInvalidClientConfig(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"empty_endpoint", func(c *Config) {
			c.Endpoint = ""
		}},
		{"malformed_endpoint", func(c *Config) {
			c.Endpoint = "http://%"
		}},
		{"missing_host", func(c *Config) {
			c.Endpoint = "https:///rpc"
		}},
		{"unsupported_scheme", func(c *Config) {
			c.Endpoint = "ftp://localhost"
		}},
		{"endpoint_credentials", func(c *Config) {
			c.Endpoint = "https://user:password@localhost"
		}},
		{"endpoint_fragment", func(c *Config) {
			c.Endpoint = "https://localhost/#fragment"
		}},
		{"zero_timeout", func(c *Config) {
			c.Timeout = 0
		}},
		{"negative_timeout", func(c *Config) {
			c.Timeout = -time.Second
		}},
		{"zero_concurrency", func(c *Config) {
			c.MaxConcurrent = 0
		}},
		{"excessive_concurrency", func(c *Config) {
			c.MaxConcurrent = 129
		}},
		{"negative_retries", func(c *Config) {
			c.MaxRetries = -1
		}},
		{"excessive_retries", func(c *Config) {
			c.MaxRetries = 6
		}},
		{"zero_retry_delay", func(c *Config) {
			c.RetryDelay = 0
		}},
		{"negative_retry_delay", func(c *Config) {
			c.RetryDelay = -time.Second
		}},
		{"excessive_retry_delay", func(c *Config) {
			c.RetryDelay = time.Minute + time.Second
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Endpoint:      "https://localhost",
				Timeout:       time.Second,
				MaxConcurrent: 4,
				MaxRetries:    2,
				RetryDelay:    time.Millisecond,
			}
			tt.mutate(&cfg)
			client, err := NewClient(cfg)
			if err == nil || client != nil {
				t.Fatal("invalid client configuration accepted")
			}
		})
	}
}

func TestCancellationDuringBackoff(t *testing.T) {
	var attempts atomic.Int32
	requestReceived := make(chan struct{})
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		if attempts.Add(1) == 1 {
			close(requestReceived)
		}
	})
	client.retryDelay = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.ChainID(ctx)
		done <- err
	}()
	select {
	case <-requestReceived:
	case <-time.After(2 * time.Second):
		t.Fatal("initial RPC request not received")
	}
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case err := <-done:
		t.Fatalf("RPC call terminated before cancellation: %v", err)
	case <-timer.C:
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected cancellation error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retry cancellation did not terminate RPC call")
	}
	if attempts.Load() != 1 {
		t.Fatalf("unexpected retry after cancellation: %d", attempts.Load())
	}
}

func TestClientConcurrencyLimit(t *testing.T) {
	const (
		limit = 2
		calls = 8
	)
	var active atomic.Int32
	var peak atomic.Int32
	var requests atomic.Int32
	entered := make(chan struct{}, calls)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() {
		releaseOnce.Do(func() {
			close(release)
		})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		requests.Add(1)
		current := active.Add(1)
		defer active.Add(-1)
		for {
			previous := peak.Load()
			if current <= previous || peak.CompareAndSwap(previous, current) {
				break
			}
		}
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result":  "0x1",
		})
	}))
	defer server.Close()
	client, err := NewClient(Config{
		Endpoint:      server.URL,
		Timeout:       10 * time.Second,
		MaxConcurrent: limit,
		MaxRetries:    0,
		RetryDelay:    time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var workers sync.WaitGroup
	defer workers.Wait()
	defer unblock()
	results := make(chan error, calls)
	for i := 0; i < calls; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			id, err := client.ChainID(ctx)
			if err == nil && id != 1 {
				err = errors.New("unexpected chain ID")
			}
			results <- err
		}()
	}
	for i := 0; i < limit; i++ {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("expected concurrent requests not received")
		}
	}
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-entered:
		t.Fatal("client concurrency limit exceeded")
	case <-timer.C:
	}
	unblock()
	for i := 0; i < calls; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("concurrent RPC calls did not complete")
		}
	}
	if peak.Load() != limit {
		t.Fatalf("unexpected peak concurrency: %d", peak.Load())
	}
	if requests.Load() != calls {
		t.Fatalf("unexpected request count: %d", requests.Load())
	}
}

func FuzzParseQuantity(f *testing.F) {
	for _, seed := range []string{"0x0", "0xff", "0x00", "", "0xzz", "0xffffffffffffffff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		value, err := parseQuantity(input)
		if err != nil {
			return
		}
		encoded := formatQuantity(value)
		decoded, err := parseQuantity(encoded)
		if err != nil || decoded != value {
			t.Fatalf("quantity round-trip failed: %q", input)
		}
	})
}
