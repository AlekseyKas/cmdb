package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/lib/pq"

	"wazuh-agent-service/internal/config"
	"wazuh-agent-service/internal/models"
)

type DB struct {
	conn *sql.DB
}

func New(cfg config.DatabaseConfig) (*DB, error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Name)

	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	if err := conn.Ping(); err != nil {
		return nil, err
	}

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		return nil, err
	}

	return db, nil
}

func (db *DB) migrate() error {
	query := `
	CREATE TABLE IF NOT EXISTS agents (
		id SERIAL PRIMARY KEY,
		wazuh_id VARCHAR(50) UNIQUE NOT NULL,
		name VARCHAR(255) NOT NULL,
		ip VARCHAR(45),
		status VARCHAR(20),
		group_name VARCHAR(255),
		version VARCHAR(50),
		last_connect TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		changes JSONB DEFAULT '{}',
		previous_state JSONB DEFAULT '{}'
	);
	CREATE INDEX IF NOT EXISTS idx_agents_wazuh_id ON agents(wazuh_id);
	CREATE INDEX IF NOT EXISTS idx_agents_group ON agents(group_name);
	CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
	`
	_, err := db.conn.Exec(query)
	return err
}

func (db *DB) UpsertAgent(agent *models.Agent) error {
	var id int
	var existingPreviousState []byte
	var existingChanges []byte

	checkQuery := `SELECT id, previous_state, changes FROM agents WHERE wazuh_id = $1`
	err := db.conn.QueryRow(checkQuery, agent.WazuhID).Scan(&id, &existingPreviousState, &existingChanges)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	currentState := map[string]interface{}{
		"name":         agent.Name,
		"ip":           agent.IP,
		"status":       agent.Status,
		"group_name":   agent.GroupName,
		"version":      agent.Version,
		"last_connect": agent.LastConnect,
	}
	currentStateJSON, _ := json.Marshal(currentState)

	var changes json.RawMessage
	if err == sql.ErrNoRows {
		changes = json.RawMessage("{}")
	} else {
		var prevState map[string]interface{}
		json.Unmarshal(existingPreviousState, &prevState)

		changedFields := make(map[string]interface{})
		var curr map[string]interface{}
		json.Unmarshal(currentStateJSON, &curr)

		for key, newVal := range curr {
			if prevVal, ok := prevState[key]; ok {
				if fmt.Sprintf("%v", prevVal) != fmt.Sprintf("%v", newVal) {
					changedFields[key] = map[string]interface{}{
						"old": prevVal,
						"new": newVal,
					}
				}
			}
		}
		changes, _ = json.Marshal(changedFields)
		if len(changes) == 0 {
			changes = json.RawMessage("{}")
		}
	}

	query := `
	INSERT INTO agents (wazuh_id, name, ip, status, group_name, version, last_connect, updated_at, changes, previous_state)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	ON CONFLICT (wazuh_id) DO UPDATE SET
		name = EXCLUDED.name,
		ip = EXCLUDED.ip,
		status = EXCLUDED.status,
		group_name = EXCLUDED.group_name,
		version = EXCLUDED.version,
		last_connect = EXCLUDED.last_connect,
		updated_at = EXCLUDED.updated_at,
		changes = EXCLUDED.changes,
		previous_state = EXCLUDED.previous_state
	`

	_, err = db.conn.Exec(query,
		agent.WazuhID, agent.Name, agent.IP, agent.Status, agent.GroupName,
		agent.Version, agent.LastConnect, time.Now(), changes, currentStateJSON)

	return err
}

func (db *DB) GetAllAgents(filter models.AgentFilter) ([]models.Agent, int, error) {
	baseQuery := "FROM agents WHERE 1=1"
	args := []interface{}{}
	argIdx := 1

	if filter.Group != "" {
		baseQuery += fmt.Sprintf(" AND group_name = $%d", argIdx)
		args = append(args, filter.Group)
		argIdx++
	}
	if filter.Status != "" {
		baseQuery += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, filter.Status)
		argIdx++
	}

	var total int
	countQuery := "SELECT COUNT(*) " + baseQuery
	if err := db.conn.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	offset := (filter.Page - 1) * filter.PerPage
	selectQuery := "SELECT id, wazuh_id, name, ip, status, group_name, version, last_connect, created_at, updated_at, changes, previous_state " + baseQuery +
		fmt.Sprintf(" ORDER BY id LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, filter.PerPage, offset)

	rows, err := db.conn.Query(selectQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var agents []models.Agent
	for rows.Next() {
		var a models.Agent
		if err := rows.Scan(&a.ID, &a.WazuhID, &a.Name, &a.IP, &a.Status, &a.GroupName,
			&a.Version, &a.LastConnect, &a.CreatedAt, &a.UpdatedAt, &a.Changes, &a.PreviousState); err != nil {
			return nil, 0, err
		}
		agents = append(agents, a)
	}

	return agents, total, nil
}

func (db *DB) GetAgentByID(wazuhID string) (*models.Agent, error) {
	var a models.Agent
	query := "SELECT id, wazuh_id, name, ip, status, group_name, version, last_connect, created_at, updated_at, changes, previous_state FROM agents WHERE wazuh_id = $1"
	err := db.conn.QueryRow(query, wazuhID).Scan(&a.ID, &a.WazuhID, &a.Name, &a.IP, &a.Status,
		&a.GroupName, &a.Version, &a.LastConnect, &a.CreatedAt, &a.UpdatedAt, &a.Changes, &a.PreviousState)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}
