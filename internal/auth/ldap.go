package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/emersion/go-smtp"
	"github.com/go-ldap/ldap/v3"
	"github.com/robertlestak/esmtpfa/internal/utils"
)

type LDAPProvider struct {
	Meta                  ProviderMeta `yaml:"meta" json:"meta"`
	Server                string       `yaml:"server" json:"server"`
	Port                  int          `yaml:"port" json:"port"`
	EnableTLS             bool         `yaml:"enable_tls" json:"enable_tls"`
	TLSCa                 string       `yaml:"tls_ca" json:"tls_ca"`
	TLSCert               string       `yaml:"tls_cert" json:"tls_cert"`
	TLSKey                string       `yaml:"tls_key" json:"tls_key"`
	TLSInsecureSkipVerify bool         `yaml:"tls_insecure_skip_verify" json:"tls_insecure_skip_verify"`
	BindUser              string       `yaml:"bind_user" json:"bind_user"`
	BindPass              string       `yaml:"bind_pass" json:"bind_pass"`
	BaseDN                string       `yaml:"base_dn" json:"base_dn"`
	FilterString          string       `yaml:"filter_string" json:"filter_string"`
	Attributes            []string     `yaml:"attributes" json:"attributes"`
	conn                  *ldap.Conn
}

// Connect connects to the LDAP server and returns the connection
func (p *LDAPProvider) Connect() (*ldap.Conn, error) {
	c, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", p.Server, p.Port))
	if err != nil {
		return c, err
	}
	if p.EnableTLS {
		tc, err := utils.TlsConfig(
			&p.EnableTLS,
			&p.TLSInsecureSkipVerify,
			&p.TLSCa,
			&p.TLSCert,
			&p.TLSKey,
		)
		if err != nil {
			return c, err
		}
		err = c.StartTLS(tc)
		if err != nil {
			return c, err
		}
	}
	p.conn = c
	return c, nil
}

// Authenticate authenticates a user in LDAP
func (p *LDAPProvider) Authenticate(username, password string) (bool, error) {
	err := p.conn.Bind(username, password)
	if err != nil {
		return false, errors.New("invalid username or password")
	}
	if err := p.conn.Bind(p.BindUser, p.BindPass); err != nil {
		return false, err
	}
	return true, nil
}

// Search searches LDAP for a user and returns DN if the user exists
func (p *LDAPProvider) Search(username string) (string, error) {
	var dn string
	err := p.conn.Bind(p.BindUser, p.BindPass)
	if err != nil {
		return dn, err
	}
	filterStr := fmt.Sprintf(p.FilterString, username)
	// if attributes do not contain "dn" add it
	if !utils.StringInSlice("dn", p.Attributes) {
		p.Attributes = append(p.Attributes, "dn")
	}
	searchRequest := ldap.NewSearchRequest(
		p.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filterStr,
		p.Attributes,
		nil,
	)
	sr, err := p.conn.Search(searchRequest)
	if err != nil {
		return dn, err
	}
	if len(sr.Entries) != 1 {
		return dn, errors.New("user does not exist in LDAP")
	}
	dn = sr.Entries[0].DN
	return dn, nil
}

func (p *LDAPProvider) LDAPAuth(username, password string) (bool, error) {
	_, err := p.Connect()
	if err != nil {
		return false, err
	}
	defer p.conn.Close()
	dn, lerr := p.Search(username)
	if lerr != nil {
		return false, lerr
	}
	auth, aerr := p.Authenticate(dn, password)
	if aerr != nil {
		return false, aerr
	}
	return auth, nil
}

func (p *LDAPProvider) Valid(state *smtp.ConnectionState, username, password string) bool {
	if p.Meta.Domain != "" {
		if state.Hostname != p.Meta.Domain {
			return false
		}
	}
	ldapUser := username
	ldapPass := password
	if !p.Meta.UniqueDomainAuth && strings.Contains(password, ":") {
		var err error
		ldapUser, ldapPass, err = utils.UserPass(password)
		if err != nil {
			return false
		}
	}
	a, err := p.LDAPAuth(ldapUser, ldapPass)
	if err != nil {
		return false
	}
	if a {
		return true
	}
	return false
}

func (p *LDAPProvider) LoadParams(params map[string]any) error {
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

func (p *LDAPProvider) Remove() error {
	if p.conn != nil {
		p.conn.Close()
	}
	return nil
}
