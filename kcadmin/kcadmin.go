// Package kcadmin is a minimal Keycloak client for dev tooling: seeding real,
// loggable-in users via the Admin REST API, and obtaining user tokens via the
// password grant (load tests, API smoke tests). It is not meant for request
// paths in production servers.
package kcadmin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to one realm on one Keycloak server as an admin.
type Client struct {
	baseURL string
	realm   string
	http    *http.Client
	token   string
}

// Login obtains an admin token from the master realm's admin-cli client and
// returns a Client bound to realm.
func Login(ctx context.Context, baseURL, realm, adminUser, adminPassword string) (*Client, error) {
	hc := &http.Client{Timeout: 10 * time.Second}
	baseURL = strings.TrimRight(baseURL, "/")
	tok, err := passwordGrant(ctx, hc, baseURL, "master", "admin-cli", adminUser, adminPassword)
	if err != nil {
		return nil, fmt.Errorf("kcadmin: admin login (check admin user/password): %w", err)
	}
	return &Client{baseURL: baseURL, realm: realm, http: hc, token: tok}, nil
}

// User is the subset of a Keycloak user representation needed to seed one.
type User struct {
	Username  string
	Email     string
	FirstName string // required: Keycloak's User Profile refuses login ("Account is not fully set up") without it
	LastName  string // required, same reason
	Password  string // set as a permanent (non-temporary) credential
}

// FindUserID returns the Keycloak user id (the token's "sub") for username, or
// "" if no such user exists. Matches the username exactly; Keycloak's free-text
// search does not reliably substring-match emails, so don't search by those.
func (c *Client) FindUserID(ctx context.Context, username string) (string, error) {
	path := fmt.Sprintf("/admin/realms/%s/users?username=%s&exact=true", url.PathEscape(c.realm), url.QueryEscape(username))
	var users []struct {
		ID string `json:"id"`
	}
	if err := c.doJSON(ctx, http.MethodGet, path, nil, http.StatusOK, &users); err != nil {
		return "", fmt.Errorf("kcadmin: lookup user %q: %w", username, err)
	}
	if len(users) == 0 {
		return "", nil
	}
	return users[0].ID, nil
}

// CreateUser creates an enabled, email-verified user and returns its id.
func (c *Client) CreateUser(ctx context.Context, u User) (string, error) {
	if u.FirstName == "" || u.LastName == "" {
		return "", errors.New("kcadmin: FirstName and LastName are required (Keycloak blocks login without them)")
	}
	payload := map[string]any{
		"username":      u.Username,
		"email":         u.Email,
		"firstName":     u.FirstName,
		"lastName":      u.LastName,
		"enabled":       true,
		"emailVerified": true,
		"credentials": []map[string]any{
			{"type": "password", "value": u.Password, "temporary": false},
		},
	}
	resp, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/admin/realms/%s/users", url.PathEscape(c.realm)), payload)
	if err != nil {
		return "", fmt.Errorf("kcadmin: create user %q: %w", u.Username, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("kcadmin: create user %q: %s", u.Username, statusText(resp))
	}
	loc := resp.Header.Get("Location")
	if i := strings.LastIndex(loc, "/"); i != -1 && i < len(loc)-1 {
		return loc[i+1:], nil
	}
	return c.FindUserID(ctx, u.Username)
}

// EnsureUser returns the id of username, creating the user if missing.
// created reports whether it was created by this call.
func (c *Client) EnsureUser(ctx context.Context, u User) (id string, created bool, err error) {
	id, err = c.FindUserID(ctx, u.Username)
	if err != nil || id != "" {
		return id, false, err
	}
	id, err = c.CreateUser(ctx, u)
	return id, err == nil, err
}

// DeleteUser deletes a user by id. Deleting an already-missing user is not an
// error.
func (c *Client) DeleteUser(ctx context.Context, id string) error {
	resp, err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/admin/realms/%s/users/%s", url.PathEscape(c.realm), url.PathEscape(id)), nil)
	if err != nil {
		return fmt.Errorf("kcadmin: delete user %s: %w", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("kcadmin: delete user %s: %s", id, statusText(resp))
	}
	return nil
}

// UserToken obtains an access token for a realm user via the password grant.
// clientID must be a client with Direct Access Grants enabled. Keep that to
// dedicated, non-production clients (e.g. one used only for load tests); a
// browser frontend's client should have it disabled.
func UserToken(ctx context.Context, baseURL, realm, clientID, username, password string) (string, error) {
	hc := &http.Client{Timeout: 10 * time.Second}
	tok, err := passwordGrant(ctx, hc, strings.TrimRight(baseURL, "/"), realm, clientID, username, password)
	if err != nil {
		return "", fmt.Errorf("kcadmin: password grant for %q via %q: %w", username, clientID, err)
	}
	return tok, nil
}

func passwordGrant(ctx context.Context, hc *http.Client, baseURL, realm, clientID, username, password string) (string, error) {
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {clientID},
		"username":   {username},
		"password":   {password},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", baseURL, url.PathEscape(realm)),
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New(statusText(resp))
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if body.AccessToken == "" {
		return "", errors.New("token response had no access_token")
	}
	return body.AccessToken, nil
}

func (c *Client) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, wantStatus int, out any) error {
	resp, err := c.do(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		return errors.New(statusText(resp))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// statusText returns the HTTP status plus Keycloak's error description, if any.
func statusText(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	var kc struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		ErrorMessage     string `json:"errorMessage"`
	}
	if json.Unmarshal(b, &kc) == nil {
		for _, s := range []string{kc.ErrorDescription, kc.ErrorMessage, kc.Error} {
			if s != "" {
				return resp.Status + ": " + s
			}
		}
	}
	return resp.Status
}
