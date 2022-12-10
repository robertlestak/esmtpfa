package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"github.com/emersion/go-smtp"
	"github.com/robertlestak/esmtpfa/internal/utils"
	log "github.com/sirupsen/logrus"
)

type HTTPBasicProvider struct {
	Meta         ProviderMeta `yaml:"meta" json:"meta"`
	URL          string       `yaml:"url" json:"url"`
	Method       string       `yaml:"method" json:"method"`
	SuccessCodes []int        `yaml:"success_codes" json:"success_codes"`
}

func (p *HTTPBasicProvider) remoteAuthValid(username, password string) bool {
	l := log.WithFields(log.Fields{
		"provider": p.Meta.Name,
		"username": username,
	})
	l.Debug("Authenticating user")
	if p.URL == "" {
		l.Error("No URL specified")
		return false
	}
	if p.Method == "" {
		p.Method = "GET"
	}
	if len(p.SuccessCodes) == 0 {
		p.SuccessCodes = []int{200}
	}
	var err error
	req, err := http.NewRequest(p.Method, p.URL, nil)
	if err != nil {
		l.WithError(err).Error("Error creating request")
		return false
	}
	req.SetBasicAuth(username, password)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		l.WithError(err).Error("Error sending request")
		return false
	}
	defer resp.Body.Close()
	for _, code := range p.SuccessCodes {
		if resp.StatusCode == code {
			l.Debug("Authentication successful")
			return true
		}
	}
	l.WithField("status", resp.StatusCode).Debug("Authentication failed")
	return false
}

func (p *HTTPBasicProvider) Valid(state *smtp.ConnectionState, username, password string) bool {
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
	if p.remoteAuthValid(un, pass) {
		return true
	}
	return false
}

func (p *HTTPBasicProvider) LoadParams(params map[string]any) error {
	params = utils.ReplaceMapEnv(params)
	jd, err := json.Marshal(params)
	if err != nil {
		return err
	}
	err = json.Unmarshal(jd, p)
	if err != nil {
		return err
	}
	if p.URL == "" {
		return errors.New("No URL specified")
	}
	return nil
}

func (p *HTTPBasicProvider) Remove() error {
	return nil
}
