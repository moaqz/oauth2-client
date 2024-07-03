# OAuth Client

An implementation of an OAuth client following the [OAuth 2.0 RFC](https://datatracker.ietf.org/doc/html/rfc6749). This implementation is for learning purposes and should not be used for real projects. If you need to implement OAuth, I highly recommend the following open-source projects:

- [goth](https://github.com/markbates/goth)
- [OAuth2 for Go](https://pkg.go.dev/golang.org/x/oauth2)

## Usage

The `cmd` folder contains an example using the OAuth client with GitHub. You only need to replace your credentials.

```go
var github = oauth2.OAuth2Client{
	ClientID:          "your-client-id",
	ClientSecret:      "your-client-secret",
	RedirectURL:       "http://localhost:3000/github/callback", // port 3000 is being used by the example.
	AuthorizeEndpoint: "https://github.com/login/oauth/authorize",
	TokenEndpoint:     "https://github.com/login/oauth/access_token",
	Scopes:            []string{},
}
```

You can find the complete example in the `cmd` folder.
