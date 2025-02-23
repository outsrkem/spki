package answer

import (
	"strconv"
	"time"
)

// Metadata represents metadata for a response.
type Metadata struct {
	Message interface{} `json:"message"` // A descriptive message.
	Time    string      `json:"time"`    // Timestamp in string format.
	Ecode   string      `json:"ecode"`   // Error code string.
}

// NewResMessage creates a custom response body map with error code, message, and payload.
func NewResMessage(ecode string, msg interface{}, payload interface{}) map[string]interface{} {
	body := make(map[string]interface{})
	if msg == "" {
		msg = "Successfully."
	}
	metadata := Metadata{
		Message: msg,
		Time:    strconv.FormatInt(time.Now().UnixNano()/1e6, 10),
		Ecode:   ecode,
	}
	body["metadata"] = metadata
	if payload != "" && payload != nil {
		body["payload"] = payload
	}
	return body
}

// ResBody creates a response body map with error code, message, and payload.
func ResBody(ecode string, msg interface{}, payload interface{}) map[string]interface{} {
	return NewResMessage(ecode, msg, payload)
}

// PageInfo represents pagination information for a data set.
type PageInfo struct {
	Page     int `json:"page"`      // Current page number.
	PageSize int `json:"page_size"` // Number of items per page.
	Total    int `json:"total"`     // Total number of items in the data set.
}

// SetPageInfo creates a PageInfo object with provided pagination information.
func SetPageInfo(pageSize, page, total int) *PageInfo {
	return &PageInfo{
		Page:     page,
		PageSize: pageSize,
		Total:    total,
	}
}
