package auth

import (
	"encoding/json"
	"strings"

	"github.com/emersion/go-smtp"
	"github.com/robertlestak/esmtpfa/internal/utils"
)

type UserPassProvider struct {
	Meta     ProviderMeta `yaml:"meta" json:"meta"`
	Username string       `yaml:"username" json:"username"`
	Password string       `yaml:"password" json:"password"`
}

func (p *UserPassProvider) Valid(state *smtp.ConnectionState, username, password string) bool {
	if p.Meta.Domain != "" {
		if state.Hostname != p.Meta.Domain {
			return false
		}
	}
	un := username
	pass := password
	if !p.Meta.UniqueDomainAuth && strings.Contains(password, ":") {
		var err error
		un, pass, err = utils.UserPass(pass)
		if err != nil {
			return false
		}
	}
	if un != p.Username {
		return false
	}
	if pass != p.Password {
		return false
	}
	return true
}

func (p *UserPassProvider) LoadParams(params map[string]any) error {
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

func (p *UserPassProvider) Remove() error {
	return nil
}
