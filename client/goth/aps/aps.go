package aps

import (
	"net/url"
	"bytes"
	"io/ioutil"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL         string = "http://localhost:9096/authorize"
	tokenURL        string = "http://localhost:9096/token"
	endpointProfile string = "http://localhost:9096/userinfo"
)

// Provider is the implementation of `goth.Provider` for accessing APS.
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	config      *oauth2.Config
	prompt      oauth2.AuthCodeOption
}

// New - Please fill the code
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,
	}
	p.config = newConfig(p, scopes)
	return p
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	newAuthURL := authURL

	if len(scopes) > 0 {
		newAuthURL = newAuthURL + "?scope=" + strings.Join(scopes, ",")
	} else {
		newAuthURL = newAuthURL + "?scope=view_user"
	}
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  newAuthURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}
	return c
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return "aps"
}

// Debug is a no-op for the APS package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth - Please fill the code
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	var opts []oauth2.AuthCodeOption
	if p.prompt != nil {
		opts = append(opts, p.prompt)
	}
	url := p.config.AuthCodeURL(state, opts...)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser - Please fill the code
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}

	response, err := http.Get(endpointProfile + "?access_token=" + url.QueryEscape(sess.AccessToken))
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		return user, err
	}
	defer response.Body.Close()

	bits, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)
	return user, err
}

func userFromReader(reader io.Reader, user *goth.User) error {

	u := struct {
		ID       string `json:"id"`
		Email    string `json:"email"`
		Location string `json:"location"`
	}{}

	//u := struct {
	//	ID        string `json:"id"`
	//	Email     string `json:"email"`
	//	Name      string `json:"name"`
	//	FirstName string `json:"given_name"`
	//	LastName  string `json:"family_name"`
	//	Link      string `json:"link"`
	//	Picture   string `json:"picture"`
	//	Location  string `json:"location"`
	//	NickName  string `json:"nickname"`
	//}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.Email = u.Email
	user.UserID = u.ID
	user.Location = u.Location
	return err
}

// RefreshTokenAvailable - Please fill the code
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// RefreshToken - Please fill the code
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(oauth2.NoContext, token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}

// SetPrompt - Please fill the code
func (p *Provider) SetPrompt(prompt ...string) {
	if len(prompt) == 0 {
		return
	}
	p.prompt = oauth2.SetAuthURLParam("prompt", strings.Join(prompt, " "))
}
