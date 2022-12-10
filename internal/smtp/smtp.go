package smtp

import (
	"io"
	"strconv"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/robertlestak/esmtpfa/internal/auth"
	"github.com/robertlestak/esmtpfa/internal/metrics"
	"github.com/robertlestak/esmtpfa/internal/utils"
	log "github.com/sirupsen/logrus"
)

var (
	AllowAnonymous bool = false
	Relay          *RelayConfig
)

type RelayConfig struct {
	Host                  string
	Port                  int
	User                  string
	Pass                  string
	From                  string
	TLSEnable             bool
	TLSInsecureSkipVerify bool
	TLSCa                 string
	TLSCrt                string
	TLSKey                string
	RequireTLS            bool
	UTF8                  bool
	BinaryMime            bool
}

// The Backend implements SMTP server methods.
type Backend struct{}

// Login handles a login command with username and password.
func (bkd *Backend) Login(state *smtp.ConnectionState, username, password string) (smtp.Session, error) {
	l := log.WithFields(log.Fields{
		"app":         "smtp",
		"fn":          "Login",
		"hostname":    state.Hostname,
		"remote_addr": state.RemoteAddr,
		"username":    username,
	})
	l.Debug("Login attempt")
	if err := auth.Valid(state, username, password); err != nil {
		l.Warn("Credentials invalid")
		return nil, smtp.ErrAuthRequired
	}
	l.Info("Credentials valid")
	return &Session{
		ProviderName: username,
	}, nil
}

// AnonymousLogin requires clients to authenticate using SMTP AUTH before sending emails
func (bkd *Backend) AnonymousLogin(state *smtp.ConnectionState) (smtp.Session, error) {
	l := log.WithFields(log.Fields{
		"app":         "smtp",
		"fn":          "AnonymousLogin",
		"hostname":    state.Hostname,
		"remote_addr": state.RemoteAddr,
	})
	l.Debug("Anonymous login attempt")
	if AllowAnonymous {
		l.Info("Anonymous login allowed")
		return &Session{}, nil
	}
	l.Warn("Anonymous login not allowed")
	return nil, smtp.ErrAuthRequired
}

// A Session is returned after successful login.
type Session struct {
	ProviderName string
	From         string
	To           []string
}

func (s *Session) Mail(from string, opts smtp.MailOptions) error {
	l := log.WithFields(log.Fields{
		"app": "smtp",
		"fn":  "Mail",
	})
	l.Debug("Mail from:", from)
	s.From = from
	return nil
}

func (s *Session) Rcpt(to string) error {
	l := log.WithFields(log.Fields{
		"app": "smtp",
		"fn":  "Rcpt",
	})
	l.Debug("Rcpt to:", to)
	s.To = append(s.To, to)
	return nil
}

func (e *Session) RelaySend(r io.Reader) error {
	l := log.WithFields(log.Fields{
		"action": "RelaySend",
		"to":     e.To,
		"from":   e.From,
	})
	l.Debug("Sending email")
	tc, err := utils.TlsConfig(
		&Relay.TLSEnable,
		&Relay.TLSInsecureSkipVerify,
		&Relay.TLSCa,
		&Relay.TLSCrt,
		&Relay.TLSKey,
	)
	if err != nil {
		l.Printf("TlsConfig error=%v", err)
		return err
	}
	start := time.Now()
	var c *smtp.Client
	if Relay.TLSEnable && tc != nil {
		l.Debug("TLS enabled")
		var err error
		c, err = smtp.DialTLS(Relay.Host+":"+strconv.Itoa(Relay.Port), tc)
		if err != nil {
			l.Errorf("smtp.DialTLS error=%v", err)
			return err
		}
	} else {
		l.Debug("TLS disabled")
		var err error
		c, err = smtp.Dial(Relay.Host + ":" + strconv.Itoa(Relay.Port))
		if err != nil {
			l.Errorf("smtp.Dial error=%v", err)
			return err
		}
	}
	if Relay.User != "" && Relay.Pass != "" {
		auth := sasl.NewPlainClient("", Relay.User, Relay.Pass)
		if err := c.Auth(auth); err != nil {
			l.Errorf("c.Auth error=%v", err)
			return err
		}
	}
	opts := &smtp.MailOptions{
		RequireTLS: Relay.RequireTLS,
		UTF8:       Relay.UTF8,
	}
	if Relay.BinaryMime {
		opts.Body = smtp.BodyBinaryMIME
	}
	var headerData []byte
	if Relay.From != "" {
		l.Debug("Setting from to:", Relay.From)
		if err := c.Mail(Relay.From, opts); err != nil {
			l.Errorf("c.Mail error=%v", err)
			return err
		}
		headerData = []byte("Reply-To: " + e.From + "\r\n")
	} else {
		if err := c.Mail(e.From, opts); err != nil {
			l.Errorf("c.Mail error=%v", err)
			return err
		}
	}
	for _, to := range e.To {
		l.Debug("Setting to to:", to)
		if err := c.Rcpt(to); err != nil {
			l.Errorf("c.Rcpt error=%v", err)
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		l.Printf("c.Data error=%v", err)
		dur := time.Since(start)
		metrics.UpstreamResponseTimeHistogram.WithLabelValues(
			Relay.Host,
			"0",
		).Observe(dur.Seconds())
		return err
	}
	if len(headerData) > 0 {
		if _, err := w.Write(headerData); err != nil {
			l.Printf("w.Write error=%v", err)
			dur := time.Since(start)
			metrics.UpstreamResponseTimeHistogram.WithLabelValues(
				Relay.Host,
				"0",
			).Observe(dur.Seconds())
			return err
		}
	}
	bc, err := io.Copy(w, r)
	if err != nil {
		l.Printf("io.Copy error=%v", err)
		dur := time.Since(start)
		metrics.UpstreamResponseTimeHistogram.WithLabelValues(
			Relay.Host,
			"0",
		).Observe(dur.Seconds())
		return err
	}
	if err := w.Close(); err != nil {
		l.Printf("w.Close error=%v", err)
		dur := time.Since(start)
		metrics.UpstreamResponseTimeHistogram.WithLabelValues(
			Relay.Host,
			"0",
		).Observe(dur.Seconds())
		return err
	}
	if err := c.Quit(); err != nil {
		l.Printf("c.Quit error=%v", err)
		dur := time.Since(start)
		metrics.UpstreamResponseTimeHistogram.WithLabelValues(
			Relay.Host,
			"0",
		).Observe(dur.Seconds())
		return err
	}
	metrics.BytesSent.WithLabelValues(e.ProviderName).Add(float64(bc))
	metrics.BytesSentFromAddress.WithLabelValues(e.ProviderName, e.From).Add(float64(bc))
	for _, to := range e.To {
		metrics.BytesSentToAddress.WithLabelValues(e.ProviderName, to).Add(float64(bc))
	}
	dur := time.Since(start)
	l = l.WithFields(log.Fields{
		"duration": dur.Seconds(),
		"bytes":    bc,
	})
	metrics.UpstreamResponseTimeHistogram.WithLabelValues(
		Relay.Host,
		"1",
	).Observe(dur.Seconds())
	metrics.MailFromTo.WithLabelValues(e.From, e.To[0], "1").Inc()
	metrics.MessagesSent.WithLabelValues(e.ProviderName).Inc()
	l.Info("Email sent")
	return nil
}

func (s *Session) Data(r io.Reader) error {
	l := log.WithFields(log.Fields{
		"app": "smtp",
		"fn":  "Data",
	})
	l.Debug("Data")
	if err := s.RelaySend(r); err != nil {
		l.Error("Error sending email:", err)
		return err
	}
	l.Debug("Email sent to queue")
	return nil
}

func (s *Session) Reset() {
	l := log.WithFields(log.Fields{
		"app": "smtp",
		"fn":  "Reset",
	})
	l.Debug("Reset")
	s.From = ""
	s.To = []string{}
}

func (s *Session) Logout() error {
	l := log.WithFields(log.Fields{
		"app": "smtp",
		"fn":  "Logout",
	})
	l.Debug("Logout")
	return nil
}

func Start(domain string, port int, tlsCA string, tlsCrt string, tlsKey string, allowInsecureAuth bool, smtpUtf8 bool, requireTls bool, binaryMime bool) error {
	l := log.WithFields(log.Fields{
		"func":              "Start",
		"domain":            domain,
		"port":              port,
		"tlsCA":             tlsCA,
		"tlsCrt":            tlsCrt,
		"tlsKey":            tlsKey,
		"allowInsecureAuth": allowInsecureAuth,
		"smtpUtf8":          smtpUtf8,
		"requireTls":        requireTls,
		"binaryMime":        binaryMime,
	})
	l.Info("Starting SMTP server")
	be := &Backend{}

	s := smtp.NewServer(be)
	portStr := strconv.Itoa(port)
	s.Addr = domain + ":" + portStr
	s.Domain = domain
	s.ReadTimeout = 30 * time.Second
	s.WriteTimeout = 30 * time.Second
	s.AllowInsecureAuth = allowInsecureAuth
	s.EnableSMTPUTF8 = smtpUtf8
	s.EnableREQUIRETLS = requireTls
	s.EnableBINARYMIME = binaryMime
	if AllowAnonymous {
		s.AuthDisabled = true
	}
	if tlsCrt != "" && tlsKey != "" {
		enableTls := true
		tlsInsecure := false
		t, err := utils.TlsConfig(&enableTls, &tlsInsecure, &tlsCA, &tlsCrt, &tlsKey)
		if err != nil {
			return err
		}
		s.TLSConfig = t
	}
	l.Debug("Starting server at ", s.Addr)
	if err := s.ListenAndServe(); err != nil {
		l.Error("Error starting server:", err)
		return err
	}
	return nil
}
