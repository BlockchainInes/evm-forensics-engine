package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

const maxResponseSize = 16 << 20

type Config struct {
	Endpoint      string
	Timeout       time.Duration
	MaxConcurrent int
	MaxRetries    int
	RetryDelay    time.Duration
}

type Client struct {
	endpoint   string
	httpClient *http.Client
	semaphore  chan struct{}
	maxRetries int
	retryDelay time.Duration
	nextID     atomic.Uint64
}

type Request struct {
	JSONRPC string `json:"jsonrpc"`
	ID      uint64 `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *RPCError       `json:"error"`
}

type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

func NewClient(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Hostname() == "" ||
		(u.Scheme != "https" && u.Scheme != "http") ||
		u.User != nil || u.Fragment != "" {
		return nil, errors.New("invalid RPC endpoint")
	}
	if cfg.Timeout <= 0 || cfg.MaxConcurrent <= 0 ||
		cfg.MaxConcurrent > 128 || cfg.MaxRetries < 0 ||
		cfg.MaxRetries > 5 || cfg.RetryDelay <= 0 ||
		cfg.RetryDelay > time.Minute {
		return nil, errors.New("invalid RPC configuration")
	}
	return &Client{
		endpoint: cfg.Endpoint,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		semaphore:  make(chan struct{}, cfg.MaxConcurrent),
		maxRetries: cfg.MaxRetries,
		retryDelay: cfg.RetryDelay,
	}, nil
}

func (c *Client) Call(
	ctx context.Context,
	method string,
	params any,
	result any,
) error {
	if method == "" || result == nil {
		return errors.New("invalid RPC call")
	}
	if params == nil {
		params = []any{}
	}
	select {
	case c.semaphore <- struct{}{}:
		defer func() { <-c.semaphore }()
	case <-ctx.Done():
		return ctx.Err()
	}
	id := c.nextID.Add(1)
	payload, err := json.Marshal(Request{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return fmt.Errorf("encode RPC request: %w", err)
	}
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		raw, retryable, err := c.execute(ctx, id, payload)
		if err == nil {
			if err := json.Unmarshal(raw, result); err != nil {
				return fmt.Errorf("decode RPC result: %w", err)
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !retryable || attempt == c.maxRetries {
			return err
		}
		delay := c.retryDelay * time.Duration(1<<attempt)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return errors.New("RPC retry limit exceeded")
}

func (c *Client) execute(
	ctx context.Context,
	id uint64,
	payload []byte,
) (json.RawMessage, bool, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.endpoint,
		bytes.NewReader(payload),
	)
	if err != nil {
		return nil, false, errors.New("create RPC request failed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, true, errors.New("RPC transport failure")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		retryable := resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode == http.StatusBadGateway ||
			resp.StatusCode == http.StatusServiceUnavailable ||
			resp.StatusCode == http.StatusGatewayTimeout
		return nil, retryable, fmt.Errorf(
			"RPC HTTP status %d", resp.StatusCode,
		)
	}
	body, err := io.ReadAll(
		io.LimitReader(resp.Body, maxResponseSize+1),
	)
	if err != nil {
		return nil, true, errors.New("read RPC response failed")
	}
	if len(body) > maxResponseSize {
		return nil, false, errors.New("RPC response size exceeded")
	}
	var decoded Response
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, false, errors.New("invalid RPC response")
	}
	if decoded.JSONRPC != "2.0" || decoded.ID != id {
		return nil, false, errors.New("RPC response identity mismatch")
	}
	if decoded.Error != nil {
		if len(decoded.Result) != 0 {
			return nil, false, errors.New("conflicting RPC response fields")
		}
		return nil, false, decoded.Error
	}
	if len(decoded.Result) == 0 {
		return nil, false, errors.New("missing RPC result")
	}
	return decoded.Result, false, nil
}
