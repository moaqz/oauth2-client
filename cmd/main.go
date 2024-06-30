package main

import (
	"fmt"
	"net/http"

	"github.com/moaqz/oauth2"
)

var github = oauth2.OAuth2Client{
	ClientID:          "",
	ClientSecret:      "",
	RedirectURL:       "http://localhost:3000/github/callback",
	AuthorizeEndpoint: "https://github.com/login/oauth/authorize",
	TokenEndpoint:     "https://github.com/login/oauth/access_token",
	Scopes:            []string{"user:email"},
}

const (
	state = "generate_a_random_string_for_every_user"
)

func githubHandler(w http.ResponseWriter, r *http.Request) {
	url := github.AuthorizationURL(state)

	http.SetCookie(w, &http.Cookie{
		Name:     "oauth2_state",
		Value:    state,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   60 * 10,
	})

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func githubCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Error(w, "Invalid request parameters", http.StatusBadRequest)
		return
	}

	storedState, err := r.Cookie("oauth2_state")
	if err != nil { // cookie not found.
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if storedState.Value != state {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	token, err := github.ExchangeCode(code)
	if err != nil {
		fmt.Println("Exchange error")
		fmt.Println("token", token)
		fmt.Println("error", err)
		http.Error(w, "Code exchange failed", http.StatusInternalServerError)
		return
	}

	fmt.Println("Token:", token)
	w.WriteHeader(http.StatusOK)
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/github", githubHandler)
	mux.HandleFunc("/github/callback", githubCallbackHandler)

	fmt.Println("Server is running on port 3000")
	http.ListenAndServe(":3000", mux)
}
