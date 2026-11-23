package proxmox

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Sentinel errors. Use errors.Is; an *APIError matches the sentinel that fits
// its status code.
var (
	// ErrUnauthorized means the API token was rejected (HTTP 401).
	ErrUnauthorized = errors.New("proxmox: authentication failed")
	// ErrForbidden means the token lacks a privilege (HTTP 403).
	ErrForbidden = errors.New("proxmox: permission denied")
	// ErrNotFound means the object (VM, node, storage, task) does not exist.
	ErrNotFound = errors.New("proxmox: not found")
	// ErrBadRequest means PVE rejected the parameters (HTTP 400).
	ErrBadRequest = errors.New("proxmox: bad request")
	// ErrServer is a 5xx response that is not a "does not exist" error.
	ErrServer = errors.New("proxmox: server error")
	// ErrTLSPin means the server certificate did not match the pinned
	// fingerprint.
	ErrTLSPin = errors.New("proxmox: server certificate does not match pinned fingerprint")
	// ErrAgentNotRunning means the QEMU guest agent did not answer.
	ErrAgentNotRunning = errors.New("proxmox: guest agent is not running")
)

// APIError is a non-2xx response from the PVE API. It never contains
// request headers (and therefore never the token).
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	// Message is the PVE reason phrase or body message.
	Message string
	// Errors holds per-parameter validation errors (HTTP 400).
	Errors map[string]string
}

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "proxmox: %s %s: %d", e.Method, e.Path, e.StatusCode)
	if e.Message != "" {
		b.WriteString(" ")
		b.WriteString(e.Message)
	}
	if len(e.Errors) > 0 {
		keys := make([]string, 0, len(e.Errors))
		for k := range e.Errors {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "; %s: %s", k, strings.TrimSpace(e.Errors[k]))
		}
	}
	return b.String()
}

// Is maps the status code (and well-known PVE messages) to sentinels.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrUnauthorized:
		return e.StatusCode == http.StatusUnauthorized
	case ErrForbidden:
		return e.StatusCode == http.StatusForbidden
	case ErrNotFound:
		return e.StatusCode == http.StatusNotFound || e.notFoundMessage()
	case ErrBadRequest:
		return e.StatusCode == http.StatusBadRequest
	case ErrServer:
		return e.StatusCode >= 500 && !e.notFoundMessage()
	case ErrAgentNotRunning:
		m := strings.ToLower(e.Message)
		return strings.Contains(m, "qemu guest agent is not running") ||
			strings.Contains(m, "guest agent is not running") || strings.Contains(m, "no qemu guest agent configured")
	}
	return false
}

// PVE reports missing objects as HTTP 500 with messages such as
// "Configuration file 'nodes/pve/qemu-server/100.conf' does not exist".
func (e *APIError) notFoundMessage() bool {
	m := strings.ToLower(e.Message)
	return e.StatusCode >= 500 && (strings.Contains(m, "does not exist") || strings.Contains(m, "no such"))
}

// Temporary reports whether retrying the request may succeed.
func (e *APIError) Temporary() bool {
	switch e.StatusCode {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// TaskError is returned when a PVE task finishes with a non-OK exit status.
type TaskError struct {
	UPID       string
	Node       string
	Type       string
	ExitStatus string
}

func (e *TaskError) Error() string {
	return fmt.Sprintf("proxmox: task %s on %s failed: %s", e.Type, e.Node, e.ExitStatus)
}
