// Copyright 2014 Tamás Gulácsi. All rights reserved.
// Use of this source code is governed by an Apache 2.0
// license that can be found in the LICENSE file.

package picago

import (
	"errors"
	"fmt"
	"net"
	"net/http"

	"golang.org/x/net/context"

	"camlistore.org/pkg/oauthutil"
	"camlistore.org/third_party/golang.org/x/oauth2"
	"camlistore.org/third_party/golang.org/x/oauth2/google"
)

const picasaScope = "https://picasaweb.google.com/data/"

var ErrCodeNeeded = errors.New("Authorization code is needed")

// Authorize authorizes using OAuth2
// the ID and secret strings can be acquired from Google for the application
// https://developers.google.com/accounts/docs/OAuth2#basicsteps
func Authorize(ID, secret string) error {
	return errors.New("Not implemented")
}

// NewClient returns an authorized http.Client usable for requests,
// caching tokens in the given file.
//
// id and secret is required, code can be empty;
//
// online decides whether the user  is at the Browser when token refresh is needed;
//
// tokenCacheFile is the cache file where the tokens will be cached.
func NewClient(id, secret, code string, online bool, tokenCacheFile string) *http.Client {
	redirectURL, acOpt := oauthutil.TitleBarRedirectURL, oauth2.AccessTypeOnline
	if !online {
		redirectURL, acOpt = "", oauth2.AccessTypeOffline
	}

	ctx := oauth2.NoContext

	config := &oauth2.Config{
		ClientID:     id,
		ClientSecret: secret,
		Endpoint:     google.Endpoint,
		Scopes:       []string{picasaScope},
		RedirectURL:  redirectURL,
	}

	src := &oauthutil.TokenSource{
		Config:    config,
		CacheFile: tokenCacheFile,

		// AuthCode provides the authorization code that Token will exchange for a token.
		// It usually is a way to prompt the user for the code. If CacheFile does not provide
		// a token and AuthCode is nil, Token returns ErrNoAuthCode.
		AuthCode: func() string {
			l, err := getListener()
			if err != nil {
				return "ERROR: " + err.Error()
			}
			donech := make(chan string, 1)

			if !online {
				config.RedirectURL = "http://" + l.Addr().String()
			}
			// Get an authorization code from the data provider.
			// ("Please ask the user if I can access this resource.")
			url := config.AuthCodeURL("picago", acOpt)
			fmt.Println("Visit this URL to get a code, then run again with code=YOUR_CODE\n")
			fmt.Println(url)

			srv := &http.Server{Handler: NewAuthorizeHandler(ctx, config, donech)}
			go srv.Serve(l)
			defer l.Close()
			return <-donech
		},
	}

	return oauth2.NewClient(context.Background(), src)
}

// NewAuthorizeHandler returns a http.HandlerFunc which will return the code on the given donech.
func NewAuthorizeHandler(ctx context.Context, config *oauth2.Config, donech chan<- string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Successfully received authorization code for ID=%s, scope=%s, for endpoints %s.",
			config.ClientID, config.Scopes, config.Endpoint)
		donech <- r.FormValue("code")
	}
}

func getListener() (*net.TCPListener, error) {
	return net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
}
