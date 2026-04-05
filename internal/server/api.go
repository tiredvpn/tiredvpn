package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tiredvpn/tiredvpn/internal/log"
)

// APIServer provides HTTP API for client management
type APIServer struct {
	registry *ClientRegistry
	store    *RedisStore
	metrics  *Metrics
	addr     string
	server   *http.Server
}

// NewAPIServer creates a new API server
func NewAPIServer(registry *ClientRegistry, store *RedisStore, addr string) *APIServer {
	return &APIServer{
		registry: registry,
		store:    store,
		metrics:  NewMetrics(registry),
		addr:     addr,
	}
}

// Metrics returns the metrics collector
func (s *APIServer) Metrics() *Metrics {
	return s.metrics
}

// Start starts the API server
func (s *APIServer) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Routes
	mux.HandleFunc("/clients", s.handleClients)
	mux.HandleFunc("/clients/", s.handleClient) // /clients/{id}
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/metrics", s.metrics.Handler())

	s.server = &http.Server{
		Addr:         s.addr,
		Handler:      s.logMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Info("API server starting on %s", s.addr)

	go func() {
		<-ctx.Done()
		s.server.Shutdown(context.Background())
	}()

	if err := s.server.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

// logMiddleware logs API requests
func (s *APIServer) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Debug("API %s %s %v", r.Method, r.URL.Path, time.Since(start))
	})
}

// handleClients handles /clients (GET list, POST create)
func (s *APIServer) handleClients(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listClients(w, r)
	case http.MethodPost:
		s.createClient(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleClient handles /clients/{id} (GET, DELETE)
func (s *APIServer) handleClient(w http.ResponseWriter, r *http.Request) {
	// Extract ID from path
	path := strings.TrimPrefix(r.URL.Path, "/clients/")
	if path == "" || path == r.URL.Path {
		http.Error(w, "Client ID required", http.StatusBadRequest)
		return
	}
	clientID := path
	if _, err := uuid.Parse(clientID); err != nil {
		http.Error(w, "Invalid client ID format", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getClient(w, r, clientID)
	case http.MethodDelete:
		s.deleteClient(w, r, clientID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// CreateClientRequest is the request body for POST /clients
type CreateClientRequest struct {
	Name      string `json:"name"`
	TunIP     string `json:"tun_ip"`
	MaxConns  int    `json:"max_conns"`
	ExpiresIn string `json:"expires_in"` // e.g., "720h" for 30 days
}

// CreateClientResponse is the response for POST /clients
type CreateClientResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Secret    string    `json:"secret"`
	TunIP     string    `json:"tun_ip,omitempty"`
	MaxConns  int       `json:"max_conns"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// createClient handles POST /clients
func (s *APIServer) createClient(w http.ResponseWriter, r *http.Request) {
	var req CreateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		s.jsonError(w, "Name is required", http.StatusBadRequest)
		return
	}

	// Parse expires_in duration
	var expiresIn time.Duration
	if req.ExpiresIn != "" {
		var err error
		expiresIn, err = time.ParseDuration(req.ExpiresIn)
		if err != nil {
			s.jsonError(w, "Invalid expires_in format (use Go duration like '720h')", http.StatusBadRequest)
			return
		}
	}

	ctx := r.Context()
	cfg, err := s.store.CreateClient(ctx, req.Name, req.TunIP, req.MaxConns, expiresIn)
	if err != nil {
		log.Error("Failed to create client: %v", err)
		s.jsonError(w, "Failed to create client", http.StatusInternalServerError)
		return
	}

	resp := CreateClientResponse{
		ID:        cfg.ID,
		Name:      cfg.Name,
		Secret:    cfg.Secret,
		TunIP:     cfg.TunIP,
		MaxConns:  cfg.MaxConns,
		Enabled:   cfg.Enabled,
		CreatedAt: cfg.CreatedAt,
		ExpiresAt: cfg.ExpiresAt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)

	log.Info("Created client via API: %s (%s)", cfg.Name, cfg.ID)
}

// ClientListItem is an item in the client list response
type ClientListItem struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	TunIP       string    `json:"tun_ip,omitempty"`
	MaxConns    int       `json:"max_conns"`
	Enabled     bool      `json:"enabled"`
	ActiveConns int       `json:"active_conns"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

// ClientListResponse is the response for GET /clients
type ClientListResponse struct {
	Clients []ClientListItem `json:"clients"`
	Total   int              `json:"total"`
}

// listClients handles GET /clients
func (s *APIServer) listClients(w http.ResponseWriter, r *http.Request) {
	clients := s.registry.ListClients()

	items := make([]ClientListItem, 0, len(clients))
	for _, cfg := range clients {
		items = append(items, ClientListItem{
			ID:          cfg.ID,
			Name:        cfg.Name,
			TunIP:       cfg.TunIP,
			MaxConns:    cfg.MaxConns,
			Enabled:     cfg.Enabled,
			ActiveConns: s.registry.GetActiveConns(cfg.ID),
			CreatedAt:   cfg.CreatedAt,
			ExpiresAt:   cfg.ExpiresAt,
		})
	}

	resp := ClientListResponse{
		Clients: items,
		Total:   len(items),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ClientDetailResponse is the response for GET /clients/{id}
type ClientDetailResponse struct {
	ID           string      `json:"id"`
	Name         string      `json:"name"`
	TunIP        string      `json:"tun_ip,omitempty"`
	MaxConns     int         `json:"max_conns"`
	MaxBandwidth int64       `json:"max_bandwidth"`
	Enabled      bool        `json:"enabled"`
	CreatedAt    time.Time   `json:"created_at"`
	ExpiresAt    time.Time   `json:"expires_at,omitempty"`
	Stats        ClientStats `json:"stats"`
}

// getClient handles GET /clients/{id}
func (s *APIServer) getClient(w http.ResponseWriter, r *http.Request, clientID string) {
	cfg := s.registry.GetByID(clientID)
	if cfg == nil {
		s.jsonError(w, "Client not found", http.StatusNotFound)
		return
	}

	stats := s.registry.GetStats(clientID)

	resp := ClientDetailResponse{
		ID:           cfg.ID,
		Name:         cfg.Name,
		TunIP:        cfg.TunIP,
		MaxConns:     cfg.MaxConns,
		MaxBandwidth: cfg.MaxBandwidth,
		Enabled:      cfg.Enabled,
		CreatedAt:    cfg.CreatedAt,
		ExpiresAt:    cfg.ExpiresAt,
		Stats:        stats,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// deleteClient handles DELETE /clients/{id}
func (s *APIServer) deleteClient(w http.ResponseWriter, r *http.Request, clientID string) {
	ctx := r.Context()

	cfg := s.registry.GetByID(clientID)
	if cfg == nil {
		s.jsonError(w, "Client not found", http.StatusNotFound)
		return
	}

	if err := s.store.DeleteClient(ctx, clientID); err != nil {
		log.Error("Failed to delete client: %v", err)
		s.jsonError(w, "Failed to delete client", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"deleted": true,
		"id":      clientID,
		"name":    cfg.Name,
	})

	log.Info("Deleted client via API: %s (%s)", cfg.Name, clientID)
}

// StatsResponse is the response for GET /stats
type StatsResponse struct {
	TotalClients     int           `json:"total_clients"`
	TotalConnections int           `json:"total_connections"`
	ClientStats      []ClientStats `json:"client_stats"`
}

// handleStats handles GET /stats
func (s *APIServer) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clients := s.registry.ListClients()

	var totalConns int
	stats := make([]ClientStats, 0, len(clients))

	for _, cfg := range clients {
		st := s.registry.GetStats(cfg.ID)
		stats = append(stats, st)
		totalConns += st.ActiveConns
	}

	resp := StatsResponse{
		TotalClients:     len(clients),
		TotalConnections: totalConns,
		ClientStats:      stats,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleHealth handles GET /health
func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check Redis connection
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := s.store.Client().Ping(ctx).Err(); err != nil {
		s.jsonError(w, fmt.Sprintf("Redis unhealthy: %v", err), http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "healthy",
		"clients": s.registry.ClientCount(),
	})
}

// jsonError writes a JSON error response
func (s *APIServer) jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": message,
		"code":  code,
	})
}
