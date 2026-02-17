package wazuh

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"wazuh-agent-service/internal/config"
	"wazuh-agent-service/internal/models"
)

type Client struct {
	baseURL     string
	username    string
	password    string
	token       string
	tokenExpiry time.Time
	client      *http.Client
}

func NewClient(cfg config.WazuhConfig) *Client {
	return &Client{
		baseURL:  cfg.URL,
		username: cfg.Username,
		password: cfg.Password,
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) login() error {
	url := fmt.Sprintf("%s/security/user/authenticate", c.baseURL)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed with status: %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid response format")
	}

	token, ok := data["token"].(string)
	if !ok {
		return fmt.Errorf("token not found in response")
	}

	c.token = token
	c.tokenExpiry = time.Now().Add(10 * time.Hour)
	return nil
}

func (c *Client) ensureToken() error {
	if c.token == "" || time.Now().After(c.tokenExpiry) {
		return c.login()
	}
	return nil
}

func (c *Client) GetAgents() ([]models.WazuhAgent, error) {
	if err := c.ensureToken(); err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/agents", c.baseURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		c.token = ""
		c.tokenExpiry = time.Time{}
		if err := c.ensureToken(); err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
		resp, err = c.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get agents: status=%d body=%s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	data, ok := result["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response format")
	}

	items, ok := data["items"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("no items in response")
	}

	var agents []models.WazuhAgent
	for _, item := range items {
		itemMap := item.(map[string]interface{})

		group := ""
		if groups, ok := itemMap["group"].([]interface{}); ok && len(groups) > 0 {
			group = groups[0].(string)
		}

		agent := models.WazuhAgent{
			ID:          fmt.Sprintf("%v", itemMap["id"]),
			Name:        fmt.Sprintf("%v", itemMap["name"]),
			IP:          fmt.Sprintf("%v", itemMap["ip"]),
			Status:      fmt.Sprintf("%v", itemMap["status"]),
			Group:       group,
			Version:     fmt.Sprintf("%v", itemMap["version"]),
			LastConnect: int64(itemMap["lastKeepAlive"].(float64)),
		}
		agents = append(agents, agent)
	}

	return agents, nil
}
