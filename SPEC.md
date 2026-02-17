# Wazuh Agent Integration Microservice

## Project Overview
- **Project name**: wazuh-agent-service
- **Type**: REST API microservice
- **Core functionality**: Integration with Wazuh API to sync agent data to PostgreSQL with change tracking
- **Target users**: Internal systems requiring agent monitoring data

## Functionality Specification

### Core Features

1. **Wazuh API Integration**
   - Connect to Wazuh API using basic auth
   - Fetch list of all agents from Wazuh
   - Configurable sync interval (default: 5 minutes)

2. **Data Storage (PostgreSQL)**
   - Store agent data: ID, name, IP, status, group, version, last connect time
   - Track changes between syncs in separate `changes` JSON field
   - Store previous state for comparison

3. **Change Detection**
   - Compare current agent state with previous state
   - Store changed fields in `changes` JSONB column
   - Changes include: status, IP, group, version, last_connect

4. **REST API Endpoints**
   - `GET /api/agents` - List all agents (paginated)
   - `GET /api/agents/:id` - Get specific agent by Wazuh ID
   - `GET /api/agents?group=<name>` - Filter agents by group

### Data Model

```sql
CREATE TABLE agents (
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

CREATE INDEX idx_agents_wazuh_id ON agents(wazuh_id);
CREATE INDEX idx_agents_group ON agents(group_name);
CREATE INDEX idx_agents_status ON agents(status);
```

### Configuration (config.yaml)
```yaml
database:
  host: "localhost"
  port: 5432
  user: "postgres"
  password: "password"
  name: "wazuh_db"

wazuh:
  url: "http://localhost:55000"
  username: "wazuh"
  password: "wazuh"

app:
  host: "0.0.0.0"
  port: 8080
  sync_interval: 300
```

## Acceptance Criteria

1. Service connects to Wazuh API and fetches agents successfully
2. Agent data is stored in PostgreSQL with proper schema
3. Changes between syncs are detected and stored in `changes` field
4. All three API endpoints return correct data:
   - GET /api/agents returns paginated list
   - GET /api/agents/:id returns specific agent
   - GET /api/agents?group=<name> filters by group
5. Code compiles without errors
6. Unit tests cover core functionality
