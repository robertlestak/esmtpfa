package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	gsmtp "github.com/emersion/go-smtp"
	"github.com/gorilla/mux"
	"github.com/robertlestak/esmtpfa/internal/auth"
	"github.com/robertlestak/esmtpfa/internal/smtp"
	log "github.com/sirupsen/logrus"
)

var (
	AllowAnonymous bool
)

type Email struct {
	From string   `json:"from"`
	To   []string `json:"to"`
	Data []byte   `json:"data"`
}

func (e *Email) Send() error {
	l := log.WithFields(log.Fields{
		"app":  "server",
		"fn":   "Send",
		"from": e.From,
		"to":   e.To,
	})
	l.Info("Sending email")
	s := &smtp.Session{
		From: e.From,
		To:   e.To,
	}
	reader := bytes.NewReader(e.Data)
	if err := s.RelaySend(reader); err != nil {
		l.WithError(err).Error("Failed to send email")
		return err
	}
	return nil
}

func requestAuthenticated(r *http.Request) bool {
	l := log.WithFields(log.Fields{
		"app":  "server",
		"fn":   "requestAuthenticated",
		"host": r.Host,
	})
	l.Debug("Checking if request is authenticated")
	if AllowAnonymous {
		l.Debug("Anonymous requests are allowed")
		return true
	}
	// get provider from request
	host := strings.Split(r.Host, ":")[0]
	remoteHost := strings.Split(r.RemoteAddr, ":")[0]
	// remoteAddr is a net.Addr
	ip, err := net.ResolveIPAddr("ip", remoteHost)
	if err != nil {
		l.WithError(err).Warn("Failed to resolve IP address")
		return false
	}
	sc := &gsmtp.ConnectionState{
		Hostname:   host,
		LocalAddr:  nil,
		RemoteAddr: ip,
	}
	if r.TLS != nil {
		sc.TLS = *r.TLS
	}
	username, password, ok := r.BasicAuth()
	if !ok {
		l.Warn("No basic auth credentials found")
		return false
	}
	p, err := auth.ProviderFromRequest(sc, username, password)
	if err != nil {
		l.WithError(err).Warn("Failed to get provider from request")
		return false
	}
	if p == nil {
		l.Warn("No provider found for request")
		return false
	}
	if p.Valid(sc, username, password) {
		l.Info("Request is authenticated")
		return true
	}
	l.Warn("Request is not authenticated")
	return false
}

func handleSend(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"app":  "server",
		"fn":   "handleSend",
		"host": r.Host,
	})
	l.Info("Handling send request")
	if !requestAuthenticated(r) {
		l.Warn("Request not authenticated")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var e Email
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		l.WithError(err).Error("Failed to decode request")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := e.Send(); err != nil {
		l.WithError(err).Error("Failed to send email")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func Start(port int, certFile, keyFile string) error {
	l := log.WithFields(log.Fields{
		"app":  "server",
		"fn":   "Start",
		"port": port,
	})
	l.Debug("Starting HTTP server")
	r := mux.NewRouter()
	r.HandleFunc("/", handleSend).Methods("POST")
	if certFile != "" && keyFile != "" {
		l := log.WithFields(log.Fields{
			"cert": certFile,
			"key":  keyFile,
		})
		l.Info("Starting TLS HTTP server")
		// listen and serve with TLS config
		return http.ListenAndServeTLS(fmt.Sprintf(":%d", port),
			certFile,
			keyFile,
			r)
	} else {
		l.Info("Starting non-TLS HTTP server")
		return http.ListenAndServe(fmt.Sprintf(":%d", port), r)
	}
}
