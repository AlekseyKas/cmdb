package service

import (
	"encoding/json"
	"log"
	"time"

	"wazuh-agent-service/internal/database"
	"wazuh-agent-service/internal/models"
	"wazuh-agent-service/internal/wazuh"
)

type AgentService struct {
	db     *database.DB
	client *wazuh.Client
}

func NewAgentService(db *database.DB, client *wazuh.Client) *AgentService {
	return &AgentService{
		db:     db,
		client: client,
	}
}

func (s *AgentService) SyncAgents() error {
	agents, err := s.client.GetAgents()
	if err != nil {
		return err
	}

	for _, wa := range agents {
		var lastConnect time.Time
		if wa.LastConnect > 0 {
			lastConnect = time.Unix(wa.LastConnect/1000, 0)
		}

		agent := &models.Agent{
			WazuhID:     wa.ID,
			Name:        wa.Name,
			IP:          wa.IP,
			Status:      wa.Status,
			GroupName:   wa.Group,
			Version:     wa.Version,
			LastConnect: lastConnect,
		}

		if err := s.db.UpsertAgent(agent); err != nil {
			log.Printf("Failed to upsert agent %s: %v", wa.ID, err)
			continue
		}
	}

	log.Printf("Synced %d agents from Wazuh", len(agents))
	return nil
}

func (s *AgentService) GetAllAgents(filter models.AgentFilter) (*models.PaginatedResponse, error) {
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PerPage < 1 || filter.PerPage > 100 {
		filter.PerPage = 20
	}

	agents, total, err := s.db.GetAllAgents(filter)
	if err != nil {
		return nil, err
	}

	return &models.PaginatedResponse{
		Agents:  agents,
		Page:    filter.Page,
		PerPage: filter.PerPage,
		Total:   total,
	}, nil
}

func (s *AgentService) GetAgentByID(wazuhID string) (*models.Agent, error) {
	return s.db.GetAgentByID(wazuhID)
}

func (s *AgentService) GetAgentsByGroup(group string) (*models.PaginatedResponse, error) {
	filter := models.AgentFilter{
		Group:   group,
		Page:    1,
		PerPage: 100,
	}
	return s.GetAllAgents(filter)
}

func (s *AgentService) HasChanges(agent *models.Agent) bool {
	var changes map[string]interface{}
	if err := json.Unmarshal(agent.Changes, &changes); err != nil {
		return false
	}
	return len(changes) > 0
}
