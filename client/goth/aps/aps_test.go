package aps_test

import (
	"fmt"
	"os"
	"testing"
	"github.com/markbates/goth"
	"github.com/pcsoi/oauth/client/goth/aps"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := provider()
	a.Equal(provider.ClientKey, os.Getenv("APS_KEY"))
	a.Equal(provider.Secret, os.Getenv("APS_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := provider()

	session, err := provider.BeginAuth("test_state")
	s := session.(*aps.Session)

	a.NoError(err)
	a.Contains(s.AuthURL, "localhost:9096/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("APS_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
}

func Test_BeginAuthWithPrompt(t *testing.T) {
	// This exists because there was a panic caused by the oauth2 package when
	// the AuthCodeOption passed was nil. This test uses it, Test_BeginAuth does
	// not, to ensure both cases are covered.
	t.Parallel()
	a := assert.New(t)

	provider := provider()
	provider.SetPrompt("test", "prompts")

	session, err := provider.BeginAuth("test_state")
	s := session.(*aps.Session)

	a.NoError(err)
	a.Contains(s.AuthURL, "localhost:9096/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("APS_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "prompt=test+prompts")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), provider())
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := provider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"http://localhost:9096/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*aps.Session)

	a.Equal(session.AuthURL, "http://localhost:9096/authorize")
	a.Equal(session.AccessToken, "1234567890")
}

func provider() *aps.Provider {
	return aps.New(os.Getenv("APS_KEY"), os.Getenv("APS_SECRET"), "/foo")
}