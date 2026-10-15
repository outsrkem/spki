package answer

import (
	"time"
)

// Metadata represents response metadata including message, timestamp, and error code.
type Metadata struct {
	Message any    `json:"message,omitempty"` // Descriptive message content
	Time    int64  `json:"time"`              // Response timestamp (millisecond-level Unix time)
	Ecode   string `json:"ecode"`             // Business error code
}

// Body represents the API response structure.
type Body struct {
	Metadata *Metadata `json:"metadata"`          // Response metadata
	Payload  any       `json:"payload,omitempty"` // Optional response payload
}

// NewResMessage creates a standardized response body.
func NewResMessage(ecode string, msg any, payload any) *Body {
	var body Body

	// Set default success message when empty
	if msg == "" {
		msg = "Okay."
	}

	// Populate metadata (including current timestamp)
	body.Metadata = &Metadata{
		Message: msg,
		Time:    time.Now().UnixNano() / 1e6,
		Ecode:   ecode,
	}

	// Only set payload when non-empty (leveraging omitempty tag)
	if payload != "" && payload != nil {
		body.Payload = payload
	}

	return &body
}

// ResBody is an alias for NewResMessage, maintained for backward compatibility.
func ResBody(ecode string, msg any, payload any) *Body {
	return NewResMessage(ecode, msg, payload)
}

// PageInfo represents pagination information for dataset traversal.
type PageInfo struct {
	Offset int   `json:"offset"` // Current page number (0-based)
	Limit  int   `json:"limit"`  // Number of items per page
	Total  int64 `json:"total"`  // Total number of items in dataset
}

// SetPageInfo creates a pagination information object.
func SetPageInfo(offset, limit int, total int64) *PageInfo {
	return &PageInfo{
		Limit:  limit,
		Offset: offset,
		Total:  total,
	}
}
