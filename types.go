package main

import (
	"time"
)

type reqResData struct {
	SequenceID      int                    `json:"sequence_id"`
	Domain          string                 `json:"domain"`
	URL             string                 `json:"url"`
	Method          string                 `json:"method"`
	RequestHeaders  map[string]interface{} `json:"request_headers"`
	RequestBody     string                 `json:"request_body,omitempty"`
	ResponseStatus  float64                `json:"response_status"`
	ResponseHeaders map[string]interface{} `json:"response_headers"`
	ResponseBody    []byte                 `json:"-"`
	RequestTime     time.Time              `json:"request_time"`
	ResponseTime    time.Time              `json:"response_time"`
	TimeDiff        string                 `json:"time_diff"`
	SkipBody        bool                   `json:"-"`
}

type extractedData struct {
	ExtractType string
	Address     string
	Content     string
}
