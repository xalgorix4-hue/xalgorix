package web

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func newTestServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	if cfg == nil {
		cfg = &config.Config{RateLimitRequests: 60, RateLimitWindow: 60}
	}
	if cfg.RateLimitRequests == 0 {
		cfg.RateLimitRequests = 60
	}
	if cfg.RateLimitWindow == 0 {
		cfg.RateLimitWindow = 60
	}
	s := NewServer(cfg, 0)
	s.dataDir = t.TempDir()
	t.Cleanup(func() {
		if s.rateLimiter != nil {
			defer func() { _ = recover() }()
			s.rateLimiter.Stop()
		}
	})
	return s
}

func resetAuthSessionsForTest() {
	authSessionsMu.Lock()
	defer authSessionsMu.Unlock()
	authSessions = make(map[string]time.Time)
}

func TestRateLimitMiddleware_EnforcesLimitAndBypassesStaticAndWS(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	defer rl.Stop()

	calls := 0
	handler := rateLimitMiddleware(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.RemoteAddr = "127.0.0.1:1111"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first request status = %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.RemoteAddr = "127.0.0.1:2222"
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429", rr.Code)
	}

	for _, path := range []string{"/ws", "/static/app.js", "/assets/logo.png"} {
		req = httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "127.0.0.1:3333"
		rr = httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s bypass status = %d, want 200", path, rr.Code)
		}
	}
	if calls != 4 {
		t.Fatalf("inner handler calls = %d, want 4", calls)
	}
}

func TestAuthHandlers_LoginStatusLogout(t *testing.T) {
	resetAuthSessionsForTest()
	s := newTestServer(t, &config.Config{
		Username:          "admin",
		Password:          "secret",
		RateLimitRequests: 60,
		RateLimitWindow:   60,
	})

	rr := httptest.NewRecorder()
	s.handleAuthStatus(rr, httptest.NewRequest(http.MethodGet, "/api/auth/status", nil))
	if !strings.Contains(rr.Body.String(), `"auth_enabled":true`) || !strings.Contains(rr.Body.String(), `"authenticated":false`) {
		t.Fatalf("unexpected unauthenticated status body: %s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	loginBody := strings.NewReader(`{"username":"admin","password":"secret"}`)
	s.handleLogin(rr, httptest.NewRequest(http.MethodPost, "/api/auth/login", loginBody))
	if rr.Code != http.StatusOK {
		t.Fatalf("login status = %d body=%q", rr.Code, rr.Body.String())
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != sessionCookieName || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge <= 0 {
		t.Fatalf("unexpected session cookie: %#v", cookie)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth/status", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	s.handleAuthStatus(rr, req)
	if !strings.Contains(rr.Body.String(), `"authenticated":true`) {
		t.Fatalf("authenticated status body: %s", rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	s.handleLogout(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("logout status = %d", rr.Code)
	}
	if isValidSession(cookie.Value) {
		t.Fatal("session remained valid after logout")
	}
}

func TestScanRequest_InternalFieldsIgnoredFromJSON(t *testing.T) {
	var req ScanRequest
	if err := json.Unmarshal([]byte(`{
		"targets":["https://example.test"],
		"instruction":"run",
		"instance_id":"spoofed",
		"is_resume":true
	}`), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.InstanceID != "" || req.IsResume {
		t.Fatalf("internal fields were set from JSON: %#v", req)
	}
}

func TestPhaseRestriction_ReconReportOnlyIsStrict(t *testing.T) {
	instruction := buildPhaseFilterInstruction([]int{1, 22})
	for _, want := range []string{
		"RECONNAISSANCE-ONLY SCOPE",
		"Do NOT run vulnerability scanners",
		"DNS records",
		"Open ports",
		"do not call report_vulnerability",
	} {
		if !strings.Contains(instruction, want) {
			t.Fatalf("phase restriction missing %q:\n%s", want, instruction)
		}
	}
	if !isReconReportOnlyPhaseSelection([]int{1, 22}) {
		t.Fatal("recon/report-only phase selection was not detected")
	}
	if isReconReportOnlyPhaseSelection([]int{1, 6, 22}) {
		t.Fatal("vulnerability phase selection was incorrectly treated as recon-only")
	}
}

func TestHandleGetScan_ReturnsLiveInstanceMetadata(t *testing.T) {
	s := newTestServer(t, nil)
	inst := &ScanInstance{
		ID:             "inst-meta",
		Name:           "Recon pass",
		Targets:        "https://meta.test",
		Status:         "running",
		StartedAt:      "2026-05-10T10:00:00Z",
		ScanMode:       "single",
		Instruction:    "recon only",
		SeverityFilter: []string{"high"},
		Phases:         []int{1, 22},
		CurrentPhase:   1,
		CompanyName:    "ACME",
		events: []WSEvent{{
			Type:         "target_started",
			Content:      "Scanning target",
			CurrentPhase: 1,
		}},
	}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()

	rr := httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodGet, "/api/scans/inst-meta", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("get scan code = %d body=%s", rr.Code, rr.Body.String())
	}

	var rec ScanRecord
	if err := json.Unmarshal(rr.Body.Bytes(), &rec); err != nil {
		t.Fatalf("decode scan record: %v", err)
	}
	if rec.Name != "Recon pass" || rec.Instruction != "recon only" || rec.CurrentPhase != 1 || len(rec.Phases) != 2 {
		t.Fatalf("live instance metadata not preserved: %#v", rec)
	}
}

func TestHandleChat_RoutesRunningInstanceByInstanceID(t *testing.T) {
	s := newTestServer(t, nil)
	events := make(chan agent.Event, 4)
	sctx := scanctx.New("chat-running", t.TempDir())
	agnt := agent.NewAgent(s.cfg, "test-agent", events, sctx)
	inst := &ScanInstance{
		ID:      "inst-running",
		Targets: "https://running.test",
		Status:  "running",
		agent:   agnt,
	}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()
	t.Cleanup(func() {
		agnt.Stop()
		sctx.Close()
	})

	rr := httptest.NewRecorder()
	body := strings.NewReader(`{"instance_id":"inst-running","message":"continue checking auth"}`)
	s.handleChat(rr, httptest.NewRequest(http.MethodPost, "/api/chat", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("chat status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "next iteration") {
		t.Fatalf("unexpected running chat response: %s", rr.Body.String())
	}
}

func TestHandleChat_AllowsFinishedInstancePostScanChat(t *testing.T) {
	s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})
	var gotMessages []string
	s.postScanChatFn = func(_ *config.Config, messages []llm.Message) (string, error) {
		for _, msg := range messages {
			gotMessages = append(gotMessages, msg.Content)
		}
		return "The scan found one high severity issue.", nil
	}
	inst := &ScanInstance{
		ID:          "inst-finished",
		Targets:     "https://done.test",
		Status:      "finished",
		StartedAt:   "2026-05-10T10:00:00Z",
		FinishedAt:  "2026-05-10T10:30:00Z",
		ScanMode:    "single",
		Iterations:  2,
		ToolCalls:   3,
		VulnCount:   1,
		TotalTokens: 100,
		Vulns: []VulnSummary{{
			ID:          "v1",
			Title:       "SQL injection",
			Severity:    "high",
			Endpoint:    "/login",
			Description: "Authentication endpoint reflected SQL errors.",
		}},
		events: []WSEvent{
			{Type: "target_started", Target: "https://done.test", Content: "Scanning https://done.test"},
			{Type: "finished", Content: "Completed with one finding"},
		},
	}
	s.instancesMu.Lock()
	s.instances[inst.ID] = inst
	s.instancesMu.Unlock()

	rr := httptest.NewRecorder()
	body := strings.NewReader(`{"instance_id":"inst-finished","message":"what did we find?"}`)
	s.handleChat(rr, httptest.NewRequest(http.MethodPost, "/api/chat", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("chat status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "one high severity issue") {
		t.Fatalf("unexpected post-scan chat response: %s", rr.Body.String())
	}
	joinedMessages := strings.Join(gotMessages, "\n")
	if !strings.Contains(joinedMessages, "post-scan chat mode") ||
		!strings.Contains(joinedMessages, "SQL injection") ||
		!strings.Contains(joinedMessages, "what did we find?") {
		t.Fatalf("LLM prompt missing completed scan context or user message: %s", joinedMessages)
	}
}

func TestUploadHandlers_ParseTargetsAndInstructions(t *testing.T) {
	s := newTestServer(t, nil)

	body, contentType := multipartBody(t, "file", "targets.txt", "https://a.test\n# ignored\n\nhttps://b.test\n")
	req := httptest.NewRequest(http.MethodPost, "/api/upload-targets", body)
	req.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()
	s.handleUploadTargets(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("upload targets status = %d body=%q", rr.Code, rr.Body.String())
	}
	var targetsResp struct {
		Targets []string `json:"targets"`
		Count   int      `json:"count"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &targetsResp); err != nil {
		t.Fatalf("decode targets response: %v", err)
	}
	if targetsResp.Count != 2 || strings.Join(targetsResp.Targets, ",") != "https://a.test,https://b.test" {
		t.Fatalf("unexpected targets response: %#v", targetsResp)
	}

	body, contentType = multipartBody(t, "file", "instructions.txt", "focus on auth flows")
	req = httptest.NewRequest(http.MethodPost, "/api/upload-instructions", body)
	req.Header.Set("Content-Type", contentType)
	rr = httptest.NewRecorder()
	s.handleUploadInstructions(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("upload instructions status = %d body=%q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "focus on auth flows") {
		t.Fatalf("unexpected instructions response: %s", rr.Body.String())
	}
}

func multipartBody(t *testing.T, field, name, content string) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	f, err := w.CreateFormFile(field, name)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatalf("write multipart: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}
	return &body, w.FormDataContentType()
}

func TestQueueStateHandlers_StatusAndClear(t *testing.T) {
	s := newTestServer(t, nil)
	s.saveQueueState([]string{"https://a.test", "https://b.test"}, 1, "notes", "dast")

	rr := httptest.NewRecorder()
	s.handleQueueStatus(rr, httptest.NewRequest(http.MethodGet, "/api/queue/status", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("queue status code = %d", rr.Code)
	}
	var status map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode queue status: %v", err)
	}
	if status["available"] != true || status["remaining"].(float64) != 1 || status["scan_mode"] != "dast" {
		t.Fatalf("unexpected queue status: %#v", status)
	}

	rr = httptest.NewRecorder()
	s.handleQueueClear(rr, httptest.NewRequest(http.MethodPost, "/api/queue/clear", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("queue clear code = %d", rr.Code)
	}
	if state := s.loadQueueState(); state != nil {
		t.Fatalf("queue state still exists after clear: %#v", state)
	}
}

func TestQueueStateHandlers_ClearInvalidAndCompletedState(t *testing.T) {
	cases := []struct {
		name  string
		write func(*testing.T, *Server)
	}{
		{
			name: "corrupt JSON",
			write: func(t *testing.T, s *Server) {
				t.Helper()
				if err := os.WriteFile(s.queueStatePath(), []byte("{not-json"), 0o644); err != nil {
					t.Fatalf("write corrupt queue: %v", err)
				}
			},
		},
		{
			name: "negative index",
			write: func(t *testing.T, s *Server) {
				t.Helper()
				s.saveQueueState([]string{"https://a.test"}, -1, "", "single")
			},
		},
		{
			name: "completed index",
			write: func(t *testing.T, s *Server) {
				t.Helper()
				s.saveQueueState([]string{"https://a.test"}, 1, "", "single")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, nil)
			tc.write(t, s)

			rr := httptest.NewRecorder()
			s.handleQueueStatus(rr, httptest.NewRequest(http.MethodGet, "/api/queue/status", nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("queue status code = %d", rr.Code)
			}
			var status map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
				t.Fatalf("decode queue status: %v", err)
			}
			if status["available"] != false {
				t.Fatalf("queue should be unavailable for invalid state: %#v", status)
			}
			if state := s.loadQueueState(); state != nil {
				t.Fatalf("invalid queue state was not cleared: %#v", state)
			}

			rr = httptest.NewRecorder()
			s.handleQueueResume(rr, httptest.NewRequest(http.MethodPost, "/api/queue/resume", nil))
			if !strings.Contains(rr.Body.String(), "No interrupted queue found") {
				t.Fatalf("unexpected resume response: %s", rr.Body.String())
			}
		})
	}
}

func TestScanPersistence_ListLatestDeleteAndRebuild(t *testing.T) {
	s := newTestServer(t, nil)
	writeScanRecord(t, s.dataDir, "target-a/2026-05-01/scan-a", ScanRecord{
		ID:        "scan-a",
		Target:    "https://a.test",
		StartedAt: "2026-05-01T10:00:00Z",
		Status:    "finished",
		Vulns:     []VulnSummary{{ID: "v1", Severity: "high"}},
	})
	writeScanRecord(t, s.dataDir, "target-b/2026-05-02/scan-b", ScanRecord{
		ID:        "scan-b",
		Target:    "https://b.test",
		StartedAt: "2026-05-02T10:00:00Z",
		Status:    "running",
		ScanMode:  "single",
	})
	writeScanRecord(t, s.dataDir, "target-b/2026-05-02/subdomain", ScanRecord{
		ID:           "subdomain",
		Target:       "https://sub.b.test",
		ParentTarget: "https://b.test",
		StartedAt:    "2026-05-02T11:00:00Z",
		Status:       "finished",
	})

	rr := httptest.NewRecorder()
	s.handleListScans(rr, httptest.NewRequest(http.MethodGet, "/api/scans", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"id":"scan-b"`) {
		t.Fatalf("list scans response: code=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodGet, "/api/scans/latest", nil))
	if !strings.Contains(rr.Body.String(), `"id":"subdomain"`) {
		t.Fatalf("latest scan did not return newest record: %s", rr.Body.String())
	}

	s.rebuildInstancesFromDisk()
	if _, ok := s.instances["subdomain"]; ok {
		t.Fatal("subdomain scan should not be rebuilt as a top-level instance")
	}
	inst := s.instances["scan-b"]
	if inst == nil || inst.Status != "stopped" || inst.StopReason != "server_restart" {
		t.Fatalf("running scan was not marked stopped on rebuild: %#v", inst)
	}

	rr = httptest.NewRecorder()
	s.handleGetScan(rr, httptest.NewRequest(http.MethodDelete, "/api/scans/scan-a", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("delete scan code = %d body=%s", rr.Code, rr.Body.String())
	}
	if _, rec := s.findScanByID("scan-a"); rec != nil {
		t.Fatal("scan-a still found after delete")
	}
}

func writeScanRecord(t *testing.T, baseDir, rel string, rec ScanRecord) {
	t.Helper()
	dir := filepath.Join(baseDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir scan dir: %v", err)
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatalf("marshal scan record: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scan.json"), data, 0o644); err != nil {
		t.Fatalf("write scan.json: %v", err)
	}
}

func TestHandleRateLimitSettings_ClampsAndReplacesLimiter(t *testing.T) {
	s := newTestServer(t, &config.Config{RateLimitRequests: 5, RateLimitWindow: 30})

	rr := httptest.NewRecorder()
	s.handleRateLimit(rr, httptest.NewRequest(http.MethodPost, "/api/settings/rate-limit", strings.NewReader(`{"requests":2000,"window":1}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("rate limit update code = %d body=%s", rr.Code, rr.Body.String())
	}
	if s.cfg.RateLimitRequests != 1000 || s.cfg.RateLimitWindow != 10 {
		t.Fatalf("config was not clamped: requests=%d window=%d", s.cfg.RateLimitRequests, s.cfg.RateLimitWindow)
	}
	if s.rateLimiter == nil {
		t.Fatal("rate limiter was not replaced")
	}
}

func TestAgentMailSettings_MasksAndPreservesExistingKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	envFile := filepath.Join(home, ".xalgorix.env")
	oldKey := "old-secret-12345678"
	if err := os.WriteFile(envFile, []byte("XALGORIX_LLM=test\nAGENTMAIL_POD=oldpod\nAGENTMAIL_API_KEY="+oldKey+"\n"), 0o644); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	s := newTestServer(t, &config.Config{
		AgentMailPod:      "oldpod",
		AgentMailAPIKey:   oldKey,
		RateLimitRequests: 60,
		RateLimitWindow:   60,
	})

	rr := httptest.NewRecorder()
	s.handleAgentMailSettings(rr, httptest.NewRequest(http.MethodGet, "/api/settings/agentmail", nil))
	var getResp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if getResp["apiKey"] != "****12345678" || getResp["hasApiKey"] != true {
		t.Fatalf("unexpected masked GET response: %#v", getResp)
	}

	rr = httptest.NewRecorder()
	body := strings.NewReader(`{"pod":"newpod","apiKey":"****12345678"}`)
	s.handleAgentMailSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/agentmail", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("preserve POST code = %d body=%s", rr.Code, rr.Body.String())
	}
	if s.cfg.AgentMailAPIKey != oldKey {
		t.Fatalf("masked POST overwrote key: %q", s.cfg.AgentMailAPIKey)
	}
	data, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	if !strings.Contains(string(data), "AGENTMAIL_API_KEY="+oldKey) || !strings.Contains(string(data), "AGENTMAIL_POD=newpod") {
		t.Fatalf("env file did not preserve old key and update pod:\n%s", string(data))
	}
	if info, err := os.Stat(envFile); err != nil {
		t.Fatalf("stat env file: %v", err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("env file mode = %#o, want 0600", info.Mode().Perm())
	}

	rr = httptest.NewRecorder()
	body = strings.NewReader(`{"pod":"newpod","apiKey":"new-secret-abcdef12"}`)
	s.handleAgentMailSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/agentmail", body))
	if rr.Code != http.StatusOK {
		t.Fatalf("new key POST code = %d body=%s", rr.Code, rr.Body.String())
	}
	if s.cfg.AgentMailAPIKey != "new-secret-abcdef12" {
		t.Fatalf("new POST did not update config key: %q", s.cfg.AgentMailAPIKey)
	}
	data, err = os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read env file after new key: %v", err)
	}
	if !strings.Contains(string(data), "AGENTMAIL_API_KEY=new-secret-abcdef12") {
		t.Fatalf("env file did not contain new key:\n%s", string(data))
	}
}

func TestInstanceAction_GetAndStopSpecificInstance(t *testing.T) {
	s := newTestServer(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.instances["inst-1"] = &ScanInstance{
		ID:        "inst-1",
		Targets:   "https://a.test",
		Status:    "running",
		StartedAt: "2026-05-02T10:00:00Z",
		cancel:    cancel,
	}

	rr := httptest.NewRecorder()
	s.handleInstanceAction(rr, httptest.NewRequest(http.MethodGet, "/api/instances/inst-1", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"id":"inst-1"`) {
		t.Fatalf("get instance response: code=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	s.handleInstanceAction(rr, httptest.NewRequest(http.MethodPost, "/api/instances/inst-1/stop", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("stop instance code = %d body=%s", rr.Code, rr.Body.String())
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("instance cancel function was not called")
	}
	if got := s.instances["inst-1"].Status; got != "stopped" {
		t.Fatalf("instance status = %q, want stopped", got)
	}
}
