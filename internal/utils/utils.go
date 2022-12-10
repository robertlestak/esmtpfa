package utils

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

func ReplaceMapEnv(m map[string]any) map[string]any {
	for k, v := range m {
		if s, ok := v.(string); ok {
			m[k] = os.ExpandEnv(s)
		}
	}
	return m
}

func TlsConfig(enableTLS *bool, TLSInsecure *bool, TLSCA *string, TLSCert *string, TLSKey *string) (*tls.Config, error) {
	l := log.WithFields(log.Fields{
		"pkg": "nats",
		"fn":  "tlsConfig",
	})
	l.Debug("Creating TLS config")
	tc := &tls.Config{}
	if enableTLS != nil && *enableTLS {
		l.Debug("Enabling TLS")
		if TLSInsecure != nil && *TLSInsecure {
			l.Debug("Enabling TLS insecure")
			tc.InsecureSkipVerify = true
		}
		if TLSCA != nil && *TLSCA != "" {
			l.Debug("Enabling TLS CA")
			caCert, err := ioutil.ReadFile(*TLSCA)
			if err != nil {
				l.Errorf("%+v", err)
				return tc, err
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tc.RootCAs = caCertPool
		}
		if TLSCert != nil && *TLSCert != "" {
			l.Debug("Enabling TLS cert")
			cert, err := tls.LoadX509KeyPair(*TLSCert, *TLSKey)
			if err != nil {
				l.Errorf("%+v", err)
				return tc, err
			}
			tc.Certificates = []tls.Certificate{cert}
		}
	}
	l.Debug("Created TLS config")
	return tc, nil
}

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func UserPass(s string) (string, string, error) {
	l := log.WithFields(log.Fields{
		"pkg": "utils",
		"fn":  "UserPass",
	})
	l.Debug("Parsing userpass")
	if s == "" {
		return "", "", errors.New("empty userpass")
	}
	spl := strings.Split(s, ":")
	var u string
	var p string
	if len(spl) > 1 {
		u = spl[0]
		p = strings.Join(spl[1:], ":")
	} else {
		return "", "", errors.New("invalid userpass")
	}
	l.Debug("Parsed userpass")
	return u, p, nil
}
