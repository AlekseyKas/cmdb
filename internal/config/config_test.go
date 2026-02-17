package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoad(t *testing.T) {
	content := `
database:
  host: "localhost"
  port: 5432
  user: "testuser"
  password: "testpass"
  name: "testdb"

wazuh:
  url: "http://localhost:55000"
  username: "admin"
  password: "secret"

app:
  host: "0.0.0.0"
  port: 8080
  sync_interval: 60
`
	tmpFile, err := os.CreateTemp("", "config*.yaml")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(content)
	assert.NoError(t, err)
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	assert.NoError(t, err)
	assert.Equal(t, "localhost", cfg.Database.Host)
	assert.Equal(t, 5432, cfg.Database.Port)
	assert.Equal(t, "testuser", cfg.Database.User)
	assert.Equal(t, "http://localhost:55000", cfg.Wazuh.URL)
	assert.Equal(t, 8080, cfg.App.Port)
	assert.Equal(t, 60, cfg.App.SyncInterval)
}

func TestLoadFileNotFound(t *testing.T) {
	_, err := Load("nonexistent.yaml")
	assert.Error(t, err)
}
