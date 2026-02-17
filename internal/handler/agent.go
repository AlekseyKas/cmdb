package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"wazuh-agent-service/internal/models"
	"wazuh-agent-service/internal/service"
)

type AgentHandler struct {
	service *service.AgentService
}

func NewAgentHandler(svc *service.AgentService) *AgentHandler {
	return &AgentHandler{service: svc}
}

func (h *AgentHandler) GetAgents(w http.ResponseWriter, r *http.Request) {
	filter := models.AgentFilter{
		Group:   r.URL.Query().Get("group"),
		Status:  r.URL.Query().Get("status"),
		Page:    1,
		PerPage: 20,
	}

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil {
			filter.Page = page
		}
	}
	if perPageStr := r.URL.Query().Get("per_page"); perPageStr != "" {
		if perPage, err := strconv.Atoi(perPageStr); err == nil {
			filter.PerPage = perPage
		}
	}

	result, err := h.service.GetAllAgents(filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *AgentHandler) GetAgent(w http.ResponseWriter, r *http.Request) {
	wazuhID := r.PathValue("id")
	if wazuhID == "" {
		http.Error(w, "agent id required", http.StatusBadRequest)
		return
	}

	agent, err := h.service.GetAgentByID(wazuhID)
	if err != nil {
		http.Error(w, "agent not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agent)
}

func (h *AgentHandler) GetAgentsByGroup(w http.ResponseWriter, r *http.Request) {
	group := r.URL.Query().Get("group")
	if group == "" {
		http.Error(w, "group parameter required", http.StatusBadRequest)
		return
	}

	result, err := h.service.GetAgentsByGroup(group)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *AgentHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/agents", h.handleAgentsRoute)
	mux.HandleFunc("GET /api/agents/{id}", h.GetAgent)
}

func (h *AgentHandler) handleAgentsRoute(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Has("group") {
		h.GetAgentsByGroup(w, r)
	} else {
		h.GetAgents(w, r)
	}
}
