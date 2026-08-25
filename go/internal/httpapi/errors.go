// Package httpapi wires the HTTP surface: request ID + structured
// logging + Server-Timing + panic-recovery middleware, auth enforcement,
// consistent JSON errors, and the route table.
package httpapi

import (
	"encoding/json"
	"net/http"
)

// APIError mirrors app/v2/webapp.py's ApiError JSON body shape exactly:
// {"error": "<code>", "detail": "<message>", "field": "<optional>"}.
type APIError struct {
	Status int    `json:"-"`
	Error  string `json:"error"`
	Detail string `json:"detail"`
	Field  string `json:"field,omitempty"`
}

func (e *APIError) WriteJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	json.NewEncoder(w).Encode(e)
}

func Err(status int, code, detail string) *APIError {
	return &APIError{Status: status, Error: code, Detail: detail}
}

func ErrField(status int, code, detail, field string) *APIError {
	return &APIError{Status: status, Error: code, Detail: detail, Field: field}
}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
