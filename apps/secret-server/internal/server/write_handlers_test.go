package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/boxlite-ai/secret-server/internal/database"
	"github.com/boxlite-ai/secret-server/internal/encryption"
	"github.com/boxlite-ai/secret-server/internal/testdb"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestIntegration exercises authentication, HTTP contracts, and persistence together.
func TestIntegration(t *testing.T) {
	dsn := os.Getenv("SECRET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set SECRET_TEST_DATABASE_URL for PostgreSQL tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	_, testURL := testdb.Create(t, ctx, admin, dsn, false)
	pool, err := pgxpool.New(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	provider, err := encryption.NewEnvKeyProvider("env:test", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := encryption.NewCipher(provider)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	config := Config{Role: "write", AuthMode: "dev", DevToken: "token"}
	handler := routes(config, pool.Ping, nil, writeRoutes(pool, cipher))
	call := func(method, path, body, token, contentType string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}
	const path = "/internal/v1/boxes/Box123456789/secrets"
	const org = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	type wireSecret struct {
		Name        string            `json:"name"`
		Value       string            `json:"value"`
		Hosts       []string          `json:"hosts"`
		Headers     map[string]string `json:"headers"`
		Placeholder string            `json:"placeholder"`
	}
	first := wireSecret{"API-KEY", "private-value-marker", []string{"EXAMPLE.com", "example.com"}, map[string]string{"Authorization": "template-marker {value}"}, "placeholder-marker"}
	second := wireSecret{"SECOND", "second-value", []string{"second.example"}, map[string]string{"X-Key": "{value}"}, "other"}
	encode := func(orgID string, secrets []wireSecret) string {
		t.Helper()
		body, err := json.Marshal(struct {
			OrgID     string       `json:"org_id"`
			CreatedBy string       `json:"created_by"`
			Secrets   []wireSecret `json:"secrets"`
		}{orgID, "creator", secrets})
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	post := func(body string) *httptest.ResponseRecorder {
		return call(http.MethodPost, path, body, "token", "application/json")
	}
	assertCode := func(w *httptest.ResponseRecorder, status int, code string) {
		t.Helper()
		var body struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != status || body.Code != code {
			t.Fatalf("status=%d body=%s, want %d %s", w.Code, w.Body.String(), status, code)
		}
	}
	assertCode(call(http.MethodPost, path, "not json", "wrong", "application/json"), 401, "unauthorized")
	assertCode(call(http.MethodPost, path, "{}", "token", "text/plain"), 415, "unsupported_media_type")
	assertCode(post(`{"secrets":[]}`), 400, "malformed_json")
	assertCode(post(`{"org_id":"a","org_id":"b","secrets":[{}]}`), 400, "malformed_json")
	assertCode(post(strings.Repeat("x", maxTransferBody+1)), 413, "payload_too_large")
	invalid := first
	invalid.Value = "bad\rvalue"
	assertCode(post(encode(org, []wireSecret{invalid})), 422, "value_invalid")

	for _, field := range []string{"hosts", "placeholder"} {
		t.Run("NUL in "+field, func(t *testing.T) {
			invalid := second
			if field == "hosts" {
				invalid.Hosts = []string{"second.example", "bad\x00host"}
			} else {
				invalid.Placeholder = "before\x00after"
			}
			w := post(encode(org, []wireSecret{first, invalid}))
			var problem struct {
				Code  string `json:"code"`
				Field string `json:"field"`
			}
			err := json.Unmarshal(w.Body.Bytes(), &problem)
			if err != nil || w.Code != 422 || problem.Code != field+"_invalid" || problem.Field != "secrets[1]."+field {
				t.Errorf("status=%d code=%q field=%q decode error=%v", w.Code, problem.Code, problem.Field, err)
			}
			var count int
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM secret WHERE box_id=$1", "Box123456789").Scan(&count); err != nil || count != 0 {
				t.Fatalf("rejected batch left %d rows: %v", count, err)
			}
		})
	}

	created := post(encode(org, []wireSecret{first, second}))
	var response struct {
		Secrets []struct {
			Name string `json:"name"`
			ID   string `json:"secret_id"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &response); err != nil || created.Code != 201 || len(response.Secrets) != 2 {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	firstID := response.Secrets[0].ID
	if !isUUID(firstID) {
		t.Fatalf("bad returned id %q", firstID)
	}
	for _, forbidden := range []string{"private-value-marker", "ciphertext", "encrypted_dek", "template-marker", "placeholder-marker"} {
		if strings.Contains(created.Body.String(), forbidden) {
			t.Fatalf("create response exposed %q", forbidden)
		}
	}
	metadata := call(http.MethodGet, "/internal/v1/secrets/"+firstID, "", "token", "")
	if metadata.Code != 200 {
		t.Fatalf("metadata: %d %s", metadata.Code, metadata.Body.String())
	}
	for _, forbidden := range []string{"private-value-marker", "ciphertext", "encrypted_dek"} {
		if strings.Contains(metadata.Body.String(), forbidden) {
			t.Fatalf("metadata exposed %q", forbidden)
		}
	}
	assertCode(call(http.MethodGet, "/internal/v1/secrets/bad", "", "token", ""), 422, "secret_id_invalid")
	assertCode(call(http.MethodGet, "/internal/v1/secrets/10000000-0000-4000-8000-000000000099", "", "token", ""), 404, "secret_not_found")

	reordered := first
	reordered.Hosts = []string{"example.COM"}
	reordered.Headers = map[string]string{"authorization": "template-marker {value}"}
	retry := post(encode(strings.ToUpper(org), []wireSecret{reordered}))
	if retry.Code != 200 {
		t.Fatalf("retry: %d %s", retry.Code, retry.Body.String())
	}
	var again struct {
		Secrets []struct {
			ID string `json:"secret_id"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(retry.Body.Bytes(), &again); err != nil || len(again.Secrets) != 1 || again.Secrets[0].ID != firstID {
		t.Fatalf("retry id: %s", retry.Body.String())
	}
	for _, mutate := range []func(*wireSecret){
		func(s *wireSecret) { s.Value = "different" },
		func(s *wireSecret) { s.Name = "API_KEY" },
		func(s *wireSecret) { s.Hosts = []string{"different.example"} },
		func(s *wireSecret) { s.Headers = map[string]string{"Authorization": "changed {value}"} },
		func(s *wireSecret) { s.Placeholder = "changed" },
	} {
		changed := first
		mutate(&changed)
		assertCode(post(encode(org, []wireSecret{changed})), 409, "secret_conflict")
	}
	added := first
	added.Name = "THIRD"
	assertCode(post(encode(org, []wireSecret{added})), 409, "box_secrets_exist")
	assertCode(post(encode("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", []wireSecret{added})), 409, "box_org_mismatch")
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM secret WHERE box_id=$1", "Box123456789").Scan(&count); err != nil || count != 2 {
		t.Fatalf("row count %d: %v", count, err)
	}

	concurrentPath := "/internal/v1/boxes/Box222222222/secrets"
	concurrentBody := encode(org, []wireSecret{first})
	responses := make(chan *httptest.ResponseRecorder, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			responses <- call(http.MethodPost, concurrentPath, concurrentBody, "token", "application/json")
		}()
	}
	wg.Wait()
	left, right := <-responses, <-responses
	var leftBody, rightBody struct {
		Secrets []struct {
			ID string `json:"secret_id"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(left.Body.Bytes(), &leftBody); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(right.Body.Bytes(), &rightBody); err != nil {
		t.Fatal(err)
	}
	statusesOK := left.Code == http.StatusCreated && right.Code == http.StatusOK || left.Code == http.StatusOK && right.Code == http.StatusCreated
	if len(leftBody.Secrets) != 1 || len(rightBody.Secrets) != 1 || leftBody.Secrets[0].ID != rightBody.Secrets[0].ID || !statusesOK {
		t.Fatalf("concurrent transfers: %d %s / %d %s", left.Code, left.Body.String(), right.Code, right.Body.String())
	}

	other := routes(Config{Role: "fetch", AuthMode: "dev", DevToken: "token"}, pool.Ping, nil, writeRoutes(pool, cipher))
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(encode(org, []wireSecret{first})))
	req.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()
	other.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("fetch role exposed write route: %d", w.Code)
	}

	for _, marker := range []string{"private-value-marker", "template-marker", "placeholder-marker"} {
		if strings.Contains(logs.String(), marker) {
			t.Fatalf("log contained %q", marker)
		}
	}
}

type unavailableKeys struct{}

func (unavailableKeys) Wrap(context.Context, []byte, []byte) (encryption.WrappedDEK, error) {
	return encryption.WrappedDEK{}, encryption.ErrProviderUnavailable
}
func (unavailableKeys) Unwrap(context.Context, encryption.WrappedDEK, []byte) ([]byte, error) {
	return nil, encryption.ErrProviderUnavailable
}

type blockedKeys struct{ started chan struct{} }

func (p blockedKeys) Wrap(ctx context.Context, _ []byte, _ []byte) (encryption.WrappedDEK, error) {
	close(p.started)
	<-ctx.Done()
	return encryption.WrappedDEK{}, ctx.Err()
}

func (blockedKeys) Unwrap(ctx context.Context, _ encryption.WrappedDEK, _ []byte) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestWriteProviderFailure(t *testing.T) {
	cipher, err := encryption.NewCipher(unavailableKeys{})
	if err != nil {
		t.Fatal(err)
	}
	h := writeRoutes(nil, cipher)
	body := `{"org_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","created_by":"user","secrets":[{"name":"KEY","value":"value","hosts":["a"],"headers":{"A":"{value}"},"placeholder":"p"}]}`
	r := httptest.NewRequest(http.MethodPost, "/internal/v1/boxes/Box123456789/secrets", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "encryption_unavailable") {
		t.Fatalf("provider: %d %s", w.Code, w.Body.String())
	}
}

func TestWriteDeadlineDuringEncryption(t *testing.T) {
	provider := blockedKeys{started: make(chan struct{})}
	cipher, err := encryption.NewCipher(provider)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	body := `{"org_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","created_by":"user","secrets":[{"name":"KEY","value":"value","hosts":["a"],"headers":{"A":"{value}"},"placeholder":"p"}]}`
	r := httptest.NewRequest(http.MethodPost, "/internal/v1/boxes/Box123456789/secrets", strings.NewReader(body)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	writeRoutes(nil, cipher).ServeHTTP(w, r)
	select {
	case <-provider.started:
	default:
		t.Fatal("key provider was not reached")
	}
	if w.Code != 503 || !strings.Contains(w.Body.String(), "request_timeout") {
		t.Fatalf("deadline: %d %s", w.Code, w.Body.String())
	}
}

func TestWriteDeadlineDuringBodyRead(t *testing.T) {
	config := Config{Role: "write", AuthMode: "dev", DevToken: "test-token"}
	handler := routes(config, nil, nil, writeRoutes(nil, nil))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 100*time.Millisecond)
		defer cancel()
		handler.ServeHTTP(w, r.WithContext(ctx))
	}))
	defer srv.Close()
	conn, err := net.DialTimeout("tcp", srv.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	const partial = "POST /internal/v1/boxes/Box123456789/secrets HTTP/1.1\r\n" +
		"Host: localhost\r\nAuthorization: Bearer test-token\r\nContent-Type: application/json\r\n" +
		"Content-Length: 2\r\n\r\n{"
	if _, err := io.WriteString(conn, partial); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("did not receive a response with the request body still incomplete: %v", err)
	}
	defer resp.Body.Close()
	var body struct{ Code string }
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || resp.StatusCode != 503 || body.Code != "request_timeout" {
		t.Fatalf("body deadline: status %d, code %q, decode error %v", resp.StatusCode, body.Code, err)
	}
}
