package auth

import (
	"errors"

	"github.com/emersion/go-smtp"
	"github.com/robertlestak/esmtpfa/internal/metrics"
	log "github.com/sirupsen/logrus"
)

func Valid(state *smtp.ConnectionState, username, password string) error {
	l := log.WithFields(log.Fields{
		"app":         "auth",
		"fn":          "Valid",
		"hostname":    state.Hostname,
		"remote_addr": state.RemoteAddr,
		"username":    username,
	})
	l.Debug("Validating credentials")
	p, err := ProviderFromRequest(state, username, password)
	if err != nil {
		l.WithError(err).Error("Failed to get provider")
		return err
	}
	if !p.Valid(state, username, password) {
		l.Warn("Credentials invalid")
		metrics.AuthRequests.WithLabelValues(username, "invalid").Inc()
		metrics.AuthFailures.WithLabelValues(username).Inc()
		return errors.New("invalid credentials")
	}
	l.Info("Credentials valid")
	metrics.AuthRequests.WithLabelValues(username, "valid").Inc()
	metrics.AuthSuccesses.WithLabelValues(username).Inc()
	return nil
}
