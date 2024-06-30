package oauth2

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type OAuth2Client struct {
	ClientID          string
	ClientSecret      string
	RedirectURL       string
	AuthorizeEndpoint string
	TokenEndpoint     string
	Scopes            []string
}

func (client *OAuth2Client) AuthorizationURL(state string) string {
	authorizationURL, _ := url.Parse(client.AuthorizeEndpoint)

	v := url.Values{
		"client_id":     {client.ClientID},
		"response_type": {"code"},
	}

	if state != "" {
		v.Set("state", state)
	}

	if client.RedirectURL != "" {
		v.Set("redirect_uri", client.RedirectURL)
	}

	if len(client.Scopes) > 0 {
		v.Set("scope", strings.Join(client.Scopes, " "))
	}

	authorizationURL.RawQuery = v.Encode()
	return authorizationURL.String()
}

func (client *OAuth2Client) ExchangeCode(code string) (*Token, error) {
	v := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {code},
		"client_id":  {client.ClientID},
	}

	if client.RedirectURL != "" {
		v.Set("redirect_uri", client.RedirectURL)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		client.TokenEndpoint,
		strings.NewReader(v.Encode()),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(
		url.QueryEscape(client.ClientID),
		url.QueryEscape(client.ClientSecret),
	)

	return client.sendTokenRequest(req)
}

type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	ErrorCode        string `json:"error_code"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

// See:
// https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
type Token struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int
}

// See:
// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
type OAuth2Error struct {
	Response *http.Response
	// rfc error fields.
	ErrorCode        string
	ErrorDescription string
	ErrorURI         string
}

func (oauthError *OAuth2Error) Error() string {
	if oauthError.ErrorCode != "" {
		return fmt.Sprintf("%s - %s", oauthError.ErrorCode, oauthError.ErrorDescription)
	}

	return fmt.Sprintf("server responded with status %s", oauthError.Response.Status)
}

func (client *OAuth2Client) sendTokenRequest(req *http.Request) (*Token, error) {
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	b, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("cannot fetch token: %v", err)
	}

	var tokenRes TokenResponse
	if err := json.Unmarshal(b, &tokenRes); err != nil {
		return nil, fmt.Errorf("cannot parse request: %v", err)
	}

	if (res.StatusCode < 200 || res.StatusCode > 299) || tokenRes.ErrorCode != "" {
		return nil, &OAuth2Error{
			Response:         res,
			ErrorCode:        tokenRes.ErrorCode,
			ErrorDescription: tokenRes.ErrorDescription,
			ErrorURI:         tokenRes.ErrorURI,
		}
	}

	if tokenRes.AccessToken == "" {
		return nil, fmt.Errorf("missing access_token")
	}

	return &Token{
		AccessToken:  tokenRes.AccessToken,
		RefreshToken: tokenRes.RefreshToken,
		TokenType:    tokenRes.TokenType,
		ExpiresIn:    tokenRes.ExpiresIn,
	}, nil
}
