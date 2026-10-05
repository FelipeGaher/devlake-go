package kcadmin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeKeycloak implements just enough of the token + admin users API.
func fakeKeycloak(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	users := map[string]string{} // username → id
	mux := http.NewServeMux()
	mux.HandleFunc("POST /realms/{realm}/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("password") != "secret" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid user credentials"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok-" + r.PathValue("realm")})
	})
	mux.HandleFunc("GET /admin/realms/example/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-master" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		out := []map[string]string{}
		if id, ok := users[r.URL.Query().Get("username")]; ok {
			out = append(out, map[string]string{"id": id})
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /admin/realms/example/users", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		defer mu.Unlock()
		name := body["username"].(string)
		if _, ok := users[name]; ok {
			w.WriteHeader(409)
			_, _ = w.Write([]byte(`{"errorMessage":"User exists with same username"}`))
			return
		}
		id := "id-" + name
		users[name] = id
		w.Header().Set("Location", "/admin/realms/example/users/"+id)
		w.WriteHeader(201)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestEnsureUserAndUserToken(t *testing.T) {
	srv := fakeKeycloak(t)
	ctx := context.Background()

	if _, err := Login(ctx, srv.URL, "example", "admin", "wrong"); err == nil || !strings.Contains(err.Error(), "Invalid user credentials") {
		t.Fatalf("bad admin password: err = %v", err)
	}
	c, err := Login(ctx, srv.URL+"/", "example", "admin", "secret")
	if err != nil {
		t.Fatal(err)
	}
	u := User{Username: "alice", Email: "alice@x.io", FirstName: "Alice", LastName: "A", Password: "pw"}
	id, created, err := c.EnsureUser(ctx, u)
	if err != nil || !created || id != "id-alice" {
		t.Fatalf("first EnsureUser: %q %v %v", id, created, err)
	}
	id, created, err = c.EnsureUser(ctx, u)
	if err != nil || created || id != "id-alice" {
		t.Fatalf("second EnsureUser: %q %v %v", id, created, err)
	}
	if _, err := c.CreateUser(ctx, u); err == nil || !strings.Contains(err.Error(), "same username") {
		t.Fatalf("duplicate CreateUser: %v", err)
	}
	if _, err := c.CreateUser(ctx, User{Username: "x"}); err == nil {
		t.Fatal("CreateUser without names: want error")
	}

	tok, err := UserToken(ctx, srv.URL, "example", "app-loadtest", "alice", "secret")
	if err != nil || tok != "tok-example" {
		t.Fatalf("UserToken: %q %v", tok, err)
	}
}
