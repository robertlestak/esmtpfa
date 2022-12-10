package auth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/robertlestak/esmtpfa/internal/utils"

	"github.com/MicahParks/keyfunc"
	"github.com/emersion/go-smtp"
	log "github.com/sirupsen/logrus"
)

type JWTProvider struct {
	Meta             ProviderMeta   `yaml:"meta" json:"meta"`
	JWKSURL          string         `yaml:"jwks_url" json:"jwks_url"`
	Iss              string         `yaml:"iss" json:"iss"`
	Sub              string         `yaml:"sub" json:"sub"`
	Aud              string         `yaml:"aud" json:"aud"`
	Claims           map[string]any `yaml:"claims" json:"claims"`
	jwtKeyfunc       jwt.Keyfunc
	jwtKeyfuncCancel context.CancelFunc
}

func (p *JWTProvider) NewJWKSProvider() error {
	l := log.WithFields(log.Fields{
		"app": "auth",
		"fn":  "JWTProvider.NewJWKSProvider",
	})
	l.Debug("Creating a new JWKS provider")

	ctx, cancel := context.WithCancel(context.Background())
	p.jwtKeyfuncCancel = cancel
	options := keyfunc.Options{
		Ctx: ctx,
		RefreshErrorHandler: func(err error) {
			l.Errorf("There was an error with the jwt.KeyFunc\nError: %s", err.Error())
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	}
	jwks, err := keyfunc.Get(p.JWKSURL, options)
	if err != nil {
		l.Error("Failed to create the JWKS from the given URL.\nError: ", err.Error())
		p.jwtKeyfuncCancel()
		return err
	}
	p.jwtKeyfunc = jwks.Keyfunc
	return nil
}

func (p *JWTProvider) ValidateJWT(token string) bool {
	l := log.WithFields(log.Fields{
		"app": "auth",
		"fn":  "JWTProvider.ValidateJWT",
	})
	l.Debug("Validating JWT")
	if p.jwtKeyfunc == nil {
		if err := p.NewJWKSProvider(); err != nil {
			l.Error("Failed to create a new JWKS provider.\nError: ", err.Error())
			return false
		}
	}
	// Parse the JWT.
	t, err := jwt.Parse(token, p.jwtKeyfunc)
	if err != nil {
		l.Error("Failed to parse the JWT.\nError: ", err.Error())
		return false
	}
	// Check if the token is valid.
	if !t.Valid {
		l.Warn("The token is invalid.")
		return false
	}
	l.Debug("The token is valid.")
	// Check if the token is expired.
	if t.Claims.Valid() != nil {
		l.Warn("The token is expired.")
		return false
	}
	l.Debug("The token is not expired.")
	if p.Iss != "" {
		// Check if the token has the correct issuer.
		if t.Claims.(jwt.MapClaims)["iss"] != p.Iss {
			l.Warn("The token does not have the correct issuer.")
			return false
		}
		l.Debug("The token has the correct issuer.")
	}
	if p.Aud != "" {
		// Check if the token has the correct audience.
		if t.Claims.(jwt.MapClaims)["aud"] != p.Aud {
			l.Warn("The token does not have the correct audience.")
			return false
		}
		l.Debug("The token has the correct audience.")
	}
	if p.Sub != "" {
		// Check if the token has the correct subject.
		if t.Claims.(jwt.MapClaims)["sub"] != p.Sub {
			l.Warn("The token does not have the correct subject.")
			return false
		}
		l.Debug("The token has the correct subject.")
	}
	// Check if the token has the correct claims.
	for k, v := range p.Claims {
		if t.Claims.(jwt.MapClaims)[k] != v {
			l.Warn("The token does not have the correct claims.")
			return false
		}
	}
	l.Debug("The token has the correct claims.")
	return true
}

func (p *JWTProvider) Valid(state *smtp.ConnectionState, username, password string) bool {
	if p.Meta.Domain != "" {
		if state.Hostname != p.Meta.Domain {
			return false
		}
	}
	if p.ValidateJWT(password) {
		return true
	}
	return false
}

func (p *JWTProvider) LoadParams(params map[string]any) error {
	params = utils.ReplaceMapEnv(params)
	jd, err := json.Marshal(params)
	if err != nil {
		return err
	}
	err = json.Unmarshal(jd, p)
	if err != nil {
		return err
	}
	return nil
}

func (p *JWTProvider) Remove() error {
	l := log.WithFields(log.Fields{
		"app": "auth",
		"fn":  "JWTProvider.Remove",
	})
	l.Debug("Removing the JWT provider")
	if p.jwtKeyfuncCancel != nil {
		p.jwtKeyfuncCancel()
	}
	return nil
}
