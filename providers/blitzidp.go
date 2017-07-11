package providers

import(
	"errors"
	"net/http"
	"fmt"
	"github.com/reaxoft/oauth2_proxy/api"
)

type BlitzIdpProvider struct {
	*ProviderData
}

func NewBlitzIdpProvider(p *ProviderData) *BlitzIdpProvider {
	p.ProviderName = "BlitzIdp"
	return &BlitzIdpProvider{ProviderData: p}
}

func makeOAuthHeader(access_token string) http.Header {
	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", access_token))
	return header
}

func (p *BlitzIdpProvider) ValidateSessionState(s *SessionState) bool {
	return validateToken(p, s.AccessToken, makeOAuthHeader(s.AccessToken))
}

func (p *BlitzIdpProvider) GetEmailAddress(s *SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = makeOAuthHeader(s.AccessToken)

	type result struct {
		Email string `json:"email"`
	}
	var r result
	err = api.RequestJson(req, &r)
	if err != nil {
		return "", err
	}
	if r.Email == "" {
		return "", errors.New("no email")
	}
	return r.Email, nil
}
