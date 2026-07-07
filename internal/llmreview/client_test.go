package llmreview_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/o-faruk/mcp-x-ray/internal/llmreview"
)

func TestClient_Review_Confirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		if req["format"] != "json" {
			t.Errorf("expected format=json, got %v", req["format"])
		}
		json.NewEncoder(w).Encode(map[string]string{
			"response": `{"confirmed": true, "reason": "genuinely instructs concealment"}`,
		})
	}))
	defer srv.Close()

	c := llmreview.New(srv.URL, "test-model")
	verdict, err := c.Review(context.Background(), "title", "detail", "some untrusted text")
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.Confirmed {
		t.Errorf("Confirmed = false, want true")
	}
	if verdict.Reason == "" {
		t.Errorf("Reason is empty")
	}
}

func TestClient_Review_Dismissed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"response": `{"confirmed": false, "reason": "benign background cache rotation"}`,
		})
	}))
	defer srv.Close()

	c := llmreview.New(srv.URL, "test-model")
	verdict, err := c.Review(context.Background(), "title", "detail", "rotates the cache key secretly")
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Confirmed {
		t.Errorf("Confirmed = true, want false")
	}
}

func TestClient_Review_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := llmreview.New(srv.URL, "test-model")
	if _, err := c.Review(context.Background(), "t", "d", "u"); err == nil {
		t.Fatal("expected an error for a 500 response")
	}
}

func TestClient_Review_MalformedVerdict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"response": "not json"})
	}))
	defer srv.Close()

	c := llmreview.New(srv.URL, "test-model")
	if _, err := c.Review(context.Background(), "t", "d", "u"); err == nil {
		t.Fatal("expected an error for a malformed model response")
	}
}

func TestClient_Ping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := llmreview.New(srv.URL, "test-model")
	if err := c.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestClient_Ping_Unreachable(t *testing.T) {
	c := llmreview.New("http://127.0.0.1:1", "test-model")
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("expected an error pinging an unreachable endpoint")
	}
}
