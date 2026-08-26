package hostagent

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// ErrDenied is returned when the agent explicitly rejected the request
// (unauthorized peer, unknown op, invalid params, or an operation-level
// denial like "no candidate update staged") -- distinct from a transport
// failure (socket missing, agent not running), which callers should
// treat as "hostagent unavailable", the same nil-reader-safe contract
// every other optional compatibility boundary in this codebase uses.
var ErrDenied = errors.New("hostagent denied the request")

type Client struct {
	SocketPath string
	Timeout    time.Duration
}

func NewClient(socketPath string) *Client {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	return &Client{SocketPath: socketPath, Timeout: 10 * time.Second}
}

func newRequestID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Call sends one request and decodes the result into out (a pointer;
// nil if the caller doesn't need the result body). Returns ErrDenied
// (wrapping the agent's own message) for any ok:false response, and a
// plain error for a transport-level failure.
func (c *Client) Call(ctx context.Context, op string, params any, out any) error {
	deadline := time.Now().Add(c.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return fmt.Errorf("hostagent unavailable: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(deadline)

	var paramsRaw json.RawMessage
	if params != nil {
		paramsRaw, err = json.Marshal(params)
		if err != nil {
			return fmt.Errorf("encoding params: %w", err)
		}
	}
	req := Request{Op: op, Params: paramsRaw, RequestID: newRequestID()}
	line, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("hostagent unavailable: %w", err)
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("hostagent unavailable: %w", err)
		}
		return fmt.Errorf("hostagent unavailable: no response")
	}
	var resp Response
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		return fmt.Errorf("hostagent returned an invalid response: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("%w: %s", ErrDenied, resp.Error)
	}
	if out != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, out); err != nil {
			return fmt.Errorf("decoding hostagent result: %w", err)
		}
	}
	return nil
}
