package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"wazuh-agent-service/internal/config"
	"wazuh-agent-service/internal/database"
	"wazuh-agent-service/internal/handler"
	"wazuh-agent-service/internal/service"
	"wazuh-agent-service/internal/wazuh"
)

func main() {
	configPath := "config.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	db, err := database.New(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	wazuhClient := wazuh.NewClient(cfg.Wazuh)
	agentService := service.NewAgentService(db, wazuhClient)
	agentHandler := handler.NewAgentHandler(agentService)

	go func() {
		if err := agentService.SyncAgents(); err != nil {
			log.Printf("Initial sync failed: %v", err)
		}
	}()

	go func() {
		ticker := time.NewTicker(time.Duration(cfg.App.SyncInterval) * time.Second)
		defer ticker.Stop()
		for {
			<-ticker.C
			if err := agentService.SyncAgents(); err != nil {
				log.Printf("Sync error: %v", err)
			}
		}
	}()

	mux := http.NewServeMux()
	agentHandler.RegisterRoutes(mux)

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	addr := fmt.Sprintf("%s:%d", cfg.App.Host, cfg.App.Port)
	log.Printf("Starting server on %s", addr)

	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
}
