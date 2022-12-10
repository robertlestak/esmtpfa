package auth

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/robertlestak/esmtpfa/internal/metrics"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

var (
	Providers             = map[string]*ProviderConfig{}
	UniqueDomainProviders = map[string]string{}
	FallbackProviders     []string
	ProviderHTTPBasic     ProviderType = "http_basic"
	ProviderHTTPHeader    ProviderType = "http_header"
	ProviderJWT           ProviderType = "jwt"
	ProviderLDAP          ProviderType = "ldap"
	ProviderUserPass      ProviderType = "userpass"
)

type ProviderType string

type ProviderConfiguration struct {
	Providers []*ProviderConfig `yaml:"providers" json:"providers"`
}

type Provider interface {
	Valid(state *smtp.ConnectionState, username, password string) bool
	LoadParams(params map[string]any) error
	Remove() error
}

type ProviderMeta struct {
	Name             string       `yaml:"name" json:"name"`
	Type             ProviderType `yaml:"type" json:"type"`
	Domain           string       `yaml:"domain" json:"domain"`
	UniqueDomainAuth bool         `yaml:"unique_domain_auth" json:"unique_domain_auth"`
	Fallback         bool         `yaml:"fallback" json:"fallback"`
}

type ProviderConfig struct {
	Meta     ProviderMeta   `yaml:"meta" json:"meta"`
	Params   map[string]any `yaml:"params" json:"params"`
	provider Provider       `yaml:"-" json:"-"`
}

func (p *ProviderConfig) Load() (*ProviderConfig, error) {
	l := log.WithFields(log.Fields{
		"app":  "auth",
		"fn":   "ProviderConfig.Load",
		"type": p.Meta.Type,
		"name": p.Meta.Name,
	})
	l.Debug("Loading provider config")
	l.Debug("Provider: ", p)
	l.Debug("Provider params: ", p.Params)
	switch p.Meta.Type {
	case ProviderHTTPBasic:
		p.provider = &HTTPBasicProvider{}
		RegisterProvider(p.Meta.Name, p)
	case ProviderHTTPHeader:
		p.provider = &HTTPHeaderProvider{}
		RegisterProvider(p.Meta.Name, p)
	case ProviderJWT:
		p.provider = &JWTProvider{}
		RegisterProvider(p.Meta.Name, p)
	case ProviderLDAP:
		p.provider = &LDAPProvider{}
		RegisterProvider(p.Meta.Name, p)
	case ProviderUserPass:
		p.provider = &UserPassProvider{}
		RegisterProvider(p.Meta.Name, p)
	default:
		return nil, errors.New("Unknown provider type: " + string(p.Meta.Type))
	}
	provider, ok := Providers[p.Meta.Name]
	if !ok {
		return nil, errors.New("Provider not registered: " + p.Meta.Name)
	}
	l.Debug("Provider: ", provider)
	err := provider.provider.LoadParams(p.Params)
	if err != nil {
		l.Error("Error loading provider params: ", err)
		return nil, err
	}
	l.Debug("Loaded provider")
	return provider, nil
}

func RegisterProvider(name string, provider *ProviderConfig) {
	l := log.WithFields(log.Fields{
		"app":              "auth",
		"fn":               "RegisterProvider",
		"provider":         name,
		"type":             provider.Meta.Type,
		"domain":           provider.Meta.Domain,
		"domain_selection": provider.Meta.UniqueDomainAuth,
		"fallback":         provider.Meta.Fallback,
	})
	l.Debug("Registering provider: ", name)
	Providers[name] = provider
	d := provider.Meta.Domain
	if d == "" {
		d = "*"
	}
	metrics.ConfiguredProviders.WithLabelValues(
		name,
		d,
		strconv.FormatBool(provider.Meta.UniqueDomainAuth),
		strconv.FormatBool(provider.Meta.Fallback),
		string(provider.Meta.Type),
	).Set(1)
}

func LoadProviderConfigFile(f string) ([]*ProviderConfig, error) {
	l := log.WithFields(log.Fields{
		"app": "auth",
		"fn":  "LoadProviderConfigFile",
	})
	l.Debug("Loading provider config from file")
	var providers ProviderConfiguration
	fd, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	// Try to load as yaml first
	err = yaml.Unmarshal(fd, &providers)
	if err != nil {
		// Try to load as json
		err = json.Unmarshal(fd, &providers)
		if err != nil {
			return nil, err
		}
	}
	l.Debug("Loaded ", len(providers.Providers), " providers")
	l.Debug("Providers: ", providers.Providers)
	if err := LoadProviderConfigs(providers.Providers); err != nil {
		return nil, err
	}
	return providers.Providers, nil
}

func HotLoadProviderConfigFile(f string) {
	l := log.WithFields(log.Fields{
		"app": "auth",
		"fn":  "HotLoadProviderConfigFile",
	})
	l.Debug("Hot loading provider config from file")
	for {
		_, err := LoadProviderConfigFile(f)
		if err != nil {
			log.Fatal(err)
		}
		time.Sleep(5 * time.Second)
	}
}

func LoadProviderConfigs(providers []*ProviderConfig) error {
	l := log.WithFields(log.Fields{
		"app": "auth",
		"fn":  "LoadProviderConfigs",
	})
	l.Debug("Loading provider configs")
	deleteProviders := make(map[string]bool)
	uniqueDomains := make(map[string]bool)
	for _, p := range Providers {
		deleteProviders[p.Meta.Name] = true
	}
	for _, p := range providers {
		pr, err := p.Load()
		if err != nil {
			return err
		}
		if pr.Meta.UniqueDomainAuth {
			if pr.Meta.Domain == "" {
				return errors.New("unique domain auth requires a domain")
			}
			if _, ok := uniqueDomains[pr.Meta.Domain]; ok {
				return errors.New("Duplicate domain: " + pr.Meta.Domain)
			}
			uniqueDomains[pr.Meta.Domain] = true
			UniqueDomainProviders[pr.Meta.Domain] = p.Meta.Name
		} else {
			for d, p := range UniqueDomainProviders {
				if p == pr.Meta.Name {
					delete(UniqueDomainProviders, d)
				}
			}
		}
		if pr.Meta.Fallback {
			l.Debug("Adding fallback provider: ", p.Meta.Name)
			FallbackProviders = append(FallbackProviders, p.Meta.Name)
		} else {
			for i, p := range FallbackProviders {
				if p == pr.Meta.Name {
					// remove from fallback providers
					before := FallbackProviders[:i]
					afterI := i + 1
					if afterI >= len(FallbackProviders) {
						FallbackProviders = before
					} else {
						after := FallbackProviders[afterI:]
						FallbackProviders = append(before, after...)
					}
				}
			}
		}
		deleteProviders[p.Meta.Name] = false
	}
	for k, v := range deleteProviders {
		if v {
			l.Info("Deleting provider: ", k)
			for i, p := range FallbackProviders {
				if p == k {
					before := FallbackProviders[:i]
					afterI := i + 1
					if afterI >= len(FallbackProviders) {
						FallbackProviders = before
					} else {
						after := FallbackProviders[afterI:]
						FallbackProviders = append(before, after...)
					}
				}
			}
			for d, p := range UniqueDomainProviders {
				if p == k {
					delete(UniqueDomainProviders, d)
				}
			}
			if err := Providers[k].provider.Remove(); err != nil {
				l.Error(err)
			}
			delete(Providers, k)
		}
	}
	return nil
}

func LoadProviderRemoteConfig(providerService string) ([]*ProviderConfig, error) {
	l := log.WithFields(log.Fields{
		"app": "auth",
		"fn":  "LoadProviderRemoteConfig",
	})
	l.Debug("Loading provider config from remote")
	var providers ProviderConfiguration
	if providerService == "" {
		return nil, errors.New("PROVIDER_SERVICE not set")
	}
	l.Debug("Provider service: ", providerService)
	resp, err := http.Get(providerService)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(body, &providers)
	if err != nil {
		return nil, err
	}
	l.Debug("Loaded ", len(providers.Providers), " providers")
	l.Debug("Providers: ", providers.Providers)
	if err := LoadProviderConfigs(providers.Providers); err != nil {
		return nil, err
	}
	return providers.Providers, nil
}

func HotLoadProviderRemote(providerService string) {
	l := log.WithFields(log.Fields{
		"app": "auth",
		"fn":  "HotLoadProviderRemote",
	})
	l.Debug("Hot loading provider config from remote")
	for {
		_, err := LoadProviderRemoteConfig(providerService)
		if err != nil {
			log.Fatal(err)
		}
		time.Sleep(30 * time.Second)
	}
}

func FallbackProviderFromRequest(state *smtp.ConnectionState, username, password string) (Provider, error) {
	l := log.WithFields(log.Fields{
		"app": "auth",
		"fn":  "FallbackProviderFromRequest",
	})
	l.Debug("Getting fallback provider")
	l.Debug("Hostname: ", state.Hostname)
	l.Debug("Remote Address: ", state.RemoteAddr)
	l.Debug("Username: ", username)
	for _, p := range FallbackProviders {
		l.Debug("Checking fallback provider: ", p)
		pr := Providers[p]
		if pr.provider.Valid(state, username, password) {
			l.Debug("Found fallback provider: ", p)
			metrics.FallbackAuthRequests.WithLabelValues(p, "1").Inc()
			return pr.provider, nil
		} else {
			metrics.FallbackAuthRequests.WithLabelValues(p, "0").Inc()
		}
	}
	return nil, errors.New("no fallback provider found")
}

func ProviderFromRequest(state *smtp.ConnectionState, username, password string) (Provider, error) {
	l := log.WithFields(log.Fields{
		"app": "auth",
		"fn":  "ProviderFromRequest",
	})
	l.Debug("Getting provider")
	l.Debug("Hostname: ", state.Hostname)
	l.Debug("Remote Address: ", state.RemoteAddr)
	l.Debug("Username: ", username)
	providerName := username
	if pn, ok := UniqueDomainProviders[state.Hostname]; ok {
		l.Debug("Found provider for unique domain: ", pn)
		providerName = pn
	}
	l.Debug("len(FallbackProviders) ", len(FallbackProviders))
	p, ok := Providers[providerName]
	if !ok && len(FallbackProviders) > 0 {
		l.Debug("Provider not found for username, trying fallback providers")
		up, err := FallbackProviderFromRequest(state, username, password)
		if err != nil {
			return nil, err
		}
		return up, nil
	} else if !ok {
		l.Debug("Provider not found for username")
		return nil, errors.New("no provider found")
	}
	l.Debug("Provider found for username")
	return p.provider, nil
}
