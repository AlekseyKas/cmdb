package service

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"wazuh-agent-service/internal/models"
)

type mockDB struct{}

func (m *mockDB) UpsertAgent(agent *models.Agent) error { return nil }
func (m *mockDB) GetAllAgents(filter models.AgentFilter) ([]models.Agent, int, error) {
	return nil, 0, nil
}
func (m *mockDB) GetAgentByID(wazuhID string) (*models.Agent, error) { return nil, nil }

type mockWazuhClient struct{}

func (m *mockWazuhClient) GetAgents() ([]models.WazuhAgent, error) { return nil, nil }

func TestAgentService(t *testing.T) {
	t.Run("has changes returns true when changes exist", func(t *testing.T) {
		changes := map[string]interface{}{
			"status": map[string]interface{}{"old": "active", "new": "disconnected"},
		}
		changesJSON, _ := json.Marshal(changes)

		agent := &models.Agent{
			Changes: changesJSON,
		}

		var changesMap map[string]interface{}
		err := json.Unmarshal(agent.Changes, &changesMap)
		assert.NoError(t, err)
		assert.True(t, len(changesMap) > 0)
	})

	t.Run("has changes returns false when no changes", func(t *testing.T) {
		agent := &models.Agent{
			Changes: json.RawMessage("{}"),
		}

		var changesMap map[string]interface{}
		err := json.Unmarshal(agent.Changes, &changesMap)
		assert.NoError(t, err)
		assert.False(t, len(changesMap) > 0)
	})
}
