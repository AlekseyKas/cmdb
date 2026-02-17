package models

import (
	"encoding/json"
	"time"
)

type Agent struct {
	ID            int             `json:"id"`
	WazuhID       string          `json:"wazuh_id"`
	Name          string          `json:"name"`
	IP            string          `json:"ip"`
	Status        string          `json:"status"`
	GroupName     string          `json:"group_name"`
	Version       string          `json:"version"`
	LastConnect   time.Time       `json:"last_connect"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	Changes       json.RawMessage `json:"changes"`
	PreviousState json.RawMessage `json:"previous_state"`
}

type WazuhAgent struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	IP          string `json:"ip"`
	Status      string `json:"status"`
	Group       string `json:"group"`
	Version     string `json:"version"`
	LastConnect int64  `json:"lastKeepAlive"`
}

type AgentFilter struct {
	Group   string
	Status  string
	Page    int
	PerPage int
}

type PaginatedResponse struct {
	Agents  []Agent `json:"agents"`
	Page    int     `json:"page"`
	PerPage int     `json:"per_page"`
	Total   int     `json:"total"`
}
