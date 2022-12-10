package main

import (
	"flag"
	"os"
	"strconv"

	"github.com/robertlestak/esmtpfa/internal/auth"
	"github.com/robertlestak/esmtpfa/internal/metrics"
	"github.com/robertlestak/esmtpfa/internal/server"
	"github.com/robertlestak/esmtpfa/internal/smtp"
	log "github.com/sirupsen/logrus"
)

var (
	Cfg *Config
)

type Config struct {
	LogLevel string `yaml:"log_level"`
	SMTP     struct {
		Addr               string `yaml:"addr"`
		EnablePlain        bool   `yaml:"enable_plain"`
		Port               int    `yaml:"port"`
		AllowInsecureAuth  bool   `yaml:"allow_insecure_auth"`
		AllowAnonymousAuth bool   `yaml:"allow_anonymous_auth"`
		EnableSMTPUTF8     bool   `yaml:"enable_smtp_utf8"`
		EnableREQUIRETLS   bool   `yaml:"enable_require_tls"`
		EnableBINARYMIME   bool   `yaml:"enable_binary_mime"`
		TLS                struct {
			Enable bool   `yaml:"enable"`
			Port   int    `yaml:"port"`
			CaCert string `yaml:"ca_cert"`
			Cert   string `yaml:"cert"`
			Key    string `yaml:"key"`
		} `yaml:"tls"`
	} `yaml:"smtp"`
	HTTPServer struct {
		Enable         bool `yaml:"enable"`
		Port           int  `yaml:"port"`
		AllowAnonymous bool `yaml:"allow_anonymous"`
		TLS            struct {
			Crt string `yaml:"crt"`
			Key string `yaml:"key"`
		} `yaml:"tls"`
	} `yaml:"http_server"`
	Relay struct {
		Addr string `yaml:"addr"`
		Port int    `yaml:"port"`
		From string `yaml:"from"`
		User string `yaml:"user"`
		Pass string `yaml:"pass"`
		TLS  struct {
			Enable             bool   `yaml:"enable"`
			InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
			Ca                 string `yaml:"ca"`
			Crt                string `yaml:"crt"`
			Key                string `yaml:"key"`
		} `yaml:"tls"`
	} `yaml:"relay"`
	ProviderConfig struct {
		File    string `yaml:"file"`
		Service string `yaml:"service"`
	} `yaml:"provider_config"`
	Metrics struct {
		Port      int    `yaml:"port"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metrics"`
}

func loadConfigFromEnv() {
	l := log.WithFields(log.Fields{
		"app": "esmtpfa",
		"fn":  "loadConfigFromEnv",
	})
	l.Debug("loading config from env")
	if Cfg == nil {
		Cfg = &Config{}
	}
	if os.Getenv("LOG_LEVEL") != "" {
		Cfg.LogLevel = os.Getenv("LOG_LEVEL")
	}
	if os.Getenv("SMTP_ADDR") != "" {
		Cfg.SMTP.Addr = os.Getenv("SMTP_ADDR")
	}
	if os.Getenv("SMTP_PLAIN_ENABLE") != "" {
		pv, err := strconv.ParseBool(os.Getenv("SMTP_PLAIN_ENABLE"))
		if err != nil {
			l.WithError(err).Error("failed to parse SMTP_PLAIN_ENABLE")
		} else {
			Cfg.SMTP.EnablePlain = pv
		}
	}
	if os.Getenv("SMTP_PORT") != "" {
		pv, err := strconv.Atoi(os.Getenv("SMTP_PORT"))
		if err != nil {
			l.WithError(err).Error("failed to parse SMTP_PORT")
		} else {
			Cfg.SMTP.Port = pv
		}
	}
	if os.Getenv("SMTP_ENABLE_SMTP_UTF8") != "" {
		pv, err := strconv.ParseBool(os.Getenv("SMTP_ENABLE_SMTP_UTF8"))
		if err != nil {
			l.WithError(err).Error("failed to parse SMTP_ENABLE_SMTP_UTF8")
		} else {
			Cfg.SMTP.EnableSMTPUTF8 = pv
		}
	}
	if os.Getenv("SMTP_ENABLE_REQUIRE_TLS") != "" {
		pv, err := strconv.ParseBool(os.Getenv("SMTP_ENABLE_REQUIRE_TLS"))
		if err != nil {
			l.WithError(err).Error("failed to parse SMTP_ENABLE_REQUIRE_TLS")
		} else {
			Cfg.SMTP.EnableREQUIRETLS = pv
		}
	}
	if os.Getenv("SMTP_ENABLE_BINARY_MIME") != "" {
		pv, err := strconv.ParseBool(os.Getenv("SMTP_ENABLE_BINARY_MIME"))
		if err != nil {
			l.WithError(err).Error("failed to parse SMTP_ENABLE_BINARY_MIME")
		} else {
			Cfg.SMTP.EnableBINARYMIME = pv
		}
	}
	if os.Getenv("SMTP_ALLOW_INSECURE_AUTH") != "" {
		pv, err := strconv.ParseBool(os.Getenv("SMTP_ALLOW_INSECURE_AUTH"))
		if err != nil {
			l.WithError(err).Error("failed to parse SMTP_ALLOW_INSECURE_AUTH")
		} else {
			Cfg.SMTP.AllowInsecureAuth = pv
		}
	}
	if os.Getenv("SMTP_ALLOW_ANONYMOUS_AUTH") != "" {
		pv, err := strconv.ParseBool(os.Getenv("SMTP_ALLOW_ANONYMOUS_AUTH"))
		if err != nil {
			l.WithError(err).Error("failed to parse SMTP_ALLOW_ANONYMOUS_AUTH")
		} else {
			Cfg.SMTP.AllowAnonymousAuth = pv
		}
	}
	if os.Getenv("SMTP_TLS_ENABLE") != "" {
		pv, err := strconv.ParseBool(os.Getenv("SMTP_TLS_ENABLE"))
		if err != nil {
			l.WithError(err).Error("failed to parse SMTP_TLS_ENABLE")
		} else {
			Cfg.SMTP.TLS.Enable = pv
		}
	}
	if os.Getenv("SMTP_TLS_PORT") != "" {
		pv, err := strconv.Atoi(os.Getenv("SMTP_TLS_PORT"))
		if err != nil {
			l.WithError(err).Error("failed to parse SMTP_TLS_PORT")
		} else {
			Cfg.SMTP.TLS.Port = pv
		}
	}
	if os.Getenv("SMTP_TLS_CA_CERT") != "" {
		Cfg.SMTP.TLS.CaCert = os.Getenv("SMTP_TLS_CA_CERT")
	}
	if os.Getenv("SMTP_TLS_CERT") != "" {
		Cfg.SMTP.TLS.Cert = os.Getenv("SMTP_TLS_CERT")
	}
	if os.Getenv("SMTP_TLS_KEY") != "" {
		Cfg.SMTP.TLS.Key = os.Getenv("SMTP_TLS_KEY")
	}
	if os.Getenv("RELAY_ADDR") != "" {
		Cfg.Relay.Addr = os.Getenv("RELAY_ADDR")
	}
	if os.Getenv("RELAY_PORT") != "" {
		pv, err := strconv.Atoi(os.Getenv("RELAY_PORT"))
		if err != nil {
			l.WithError(err).Error("failed to parse RELAY_PORT")
		} else {
			Cfg.Relay.Port = pv
		}
	}
	if os.Getenv("RELAY_FROM") != "" {
		Cfg.Relay.From = os.Getenv("RELAY_FROM")
	}
	if os.Getenv("RELAY_USER") != "" {
		Cfg.Relay.User = os.Getenv("RELAY_USER")
	}
	if os.Getenv("RELAY_PASS") != "" {
		Cfg.Relay.Pass = os.Getenv("RELAY_PASS")
	}
	if os.Getenv("RELAY_TLS_ENABLE") != "" {
		pv, err := strconv.ParseBool(os.Getenv("RELAY_TLS_ENABLE"))
		if err != nil {
			l.WithError(err).Error("failed to parse RELAY_TLS_ENABLE")
		} else {
			Cfg.Relay.TLS.Enable = pv
		}
	}
	if os.Getenv("RELAY_TLS_CA_CERT") != "" {
		Cfg.Relay.TLS.Ca = os.Getenv("RELAY_TLS_CA_CERT")
	}
	if os.Getenv("RELAY_TLS_CERT") != "" {
		Cfg.Relay.TLS.Crt = os.Getenv("RELAY_TLS_CERT")
	}
	if os.Getenv("RELAY_TLS_KEY") != "" {
		Cfg.Relay.TLS.Key = os.Getenv("RELAY_TLS_KEY")
	}
	if os.Getenv("RELAY_TLS_SKIP_VERIFY") != "" {
		pv, err := strconv.ParseBool(os.Getenv("RELAY_TLS_SKIP_VERIFY"))
		if err != nil {
			l.WithError(err).Error("failed to parse RELAY_TLS_SKIP_VERIFY")
		} else {
			Cfg.Relay.TLS.InsecureSkipVerify = pv
		}
	}
	if os.Getenv("PROVIDER_CONFIG") != "" {
		Cfg.ProviderConfig.File = os.Getenv("PROVIDER_CONFIG")
	}
	if os.Getenv("PROVIDER_CONFIG_SERVICE") != "" {
		Cfg.ProviderConfig.Service = os.Getenv("PROVIDER_CONFIG_SERVICE")
	}
	if os.Getenv("METRICS_NAMESPACE") != "" {
		Cfg.Metrics.Namespace = os.Getenv("METRICS_NAMESPACE")
	}
	if os.Getenv("METRICS_PORT") != "" {
		pv, err := strconv.Atoi(os.Getenv("METRICS_PORT"))
		if err != nil {
			l.WithError(err).Error("failed to parse METRICS_PORT")
		} else {
			Cfg.Metrics.Port = pv
		}
	}
	if os.Getenv("HTTP_ENABLE") != "" {
		pv, err := strconv.ParseBool(os.Getenv("HTTP_ENABLE"))
		if err != nil {
			l.WithError(err).Error("failed to parse HTTP_ENABLE")
		} else {
			Cfg.HTTPServer.Enable = pv
		}
	}
	if os.Getenv("HTTP_PORT") != "" {
		pv, err := strconv.Atoi(os.Getenv("HTTP_PORT"))
		if err != nil {
			l.WithError(err).Error("failed to parse HTTP_PORT")
		} else {
			Cfg.HTTPServer.Port = pv
		}
	}
	if os.Getenv("HTTP_TLS_CERT") != "" {
		Cfg.HTTPServer.TLS.Crt = os.Getenv("HTTP_TLS_CERT")
	}
	if os.Getenv("HTTP_TLS_KEY") != "" {
		Cfg.HTTPServer.TLS.Key = os.Getenv("HTTP_TLS_KEY")
	}
	if os.Getenv("HTTP_ALLOW_ANONYMOUS") != "" {
		pv, err := strconv.ParseBool(os.Getenv("HTTP_ALLOW_ANONYMOUS"))
		if err != nil {
			l.WithError(err).Error("failed to parse HTTP_ALLOW_ANONYMOUS")
		} else {
			Cfg.HTTPServer.AllowAnonymous = pv
		}
	}
}

func main() {
	l := log.WithFields(log.Fields{
		"app": "esmtpfa",
		"fn":  "main",
	})
	l.Debug("starting")
	Cfg = &Config{}
	flag.StringVar(&Cfg.LogLevel, "log-level", "info", "Log level")
	flag.StringVar(&Cfg.SMTP.Addr, "addr", "", "SMTP server address")
	flag.IntVar(&Cfg.SMTP.Port, "port", 25, "SMTP server port")
	flag.BoolVar(&Cfg.SMTP.EnablePlain, "plain", false, "Enable plain-text server")
	flag.BoolVar(&Cfg.SMTP.AllowInsecureAuth, "allow-insecure-auth", false, "Allow insecure authentication")
	flag.BoolVar(&Cfg.SMTP.AllowAnonymousAuth, "allow-anonymous-auth", false, "Allow anonymous authentication")
	flag.BoolVar(&Cfg.SMTP.EnableSMTPUTF8, "enable-smtp-utf8", false, "Enable SMTPUTF8")
	flag.BoolVar(&Cfg.SMTP.EnableBINARYMIME, "enable-binary-mime", false, "Enable BINARYMIME")
	flag.BoolVar(&Cfg.SMTP.EnableREQUIRETLS, "enable-require-tls", false, "Enable REQUIRETLS")
	flag.BoolVar(&Cfg.SMTP.TLS.Enable, "tls", false, "Enable TLS server")
	flag.IntVar(&Cfg.SMTP.TLS.Port, "tls-port", 465, "TLS port")
	flag.StringVar(&Cfg.SMTP.TLS.CaCert, "tls-ca-cert", "", "TLS CA certificate")
	flag.StringVar(&Cfg.SMTP.TLS.Cert, "tls-cert", "", "TLS certificate")
	flag.StringVar(&Cfg.SMTP.TLS.Key, "tls-key", "", "TLS key")
	flag.StringVar(&Cfg.Relay.Addr, "relay-addr", "", "Relay server address")
	flag.IntVar(&Cfg.Relay.Port, "relay-port", 25, "Relay server port")
	flag.StringVar(&Cfg.Relay.User, "relay-user", "", "Relay server user")
	flag.StringVar(&Cfg.Relay.Pass, "relay-pass", "", "Relay server password")
	flag.StringVar(&Cfg.Relay.From, "relay-from", "", "Relay server from. If set, the client-provided value will be set to reply-to header")
	flag.BoolVar(&Cfg.Relay.TLS.Enable, "relay-tls", false, "Enable TLS for Relay")
	flag.StringVar(&Cfg.Relay.TLS.Ca, "relay-tls-ca-cert", "", "TLS CA certificate for Relay")
	flag.StringVar(&Cfg.Relay.TLS.Crt, "relay-tls-cert", "", "TLS certificate for Relay")
	flag.StringVar(&Cfg.Relay.TLS.Key, "relay-tls-key", "", "TLS key for Relay")
	flag.BoolVar(&Cfg.Relay.TLS.InsecureSkipVerify, "relay-tls-skip-verify", false, "Skip TLS verification for Relay")
	flag.StringVar(&Cfg.ProviderConfig.File, "config", "config.yaml", "Configuration file")
	flag.StringVar(&Cfg.ProviderConfig.Service, "config-svc", "", "Configuration service")
	flag.StringVar(&Cfg.Metrics.Namespace, "metrics-namespace", "esmtpfa", "Metrics namespace")
	flag.IntVar(&Cfg.Metrics.Port, "metrics-port", 9090, "Metrics port")
	flag.BoolVar(&Cfg.HTTPServer.Enable, "http", false, "Enable HTTP server")
	flag.IntVar(&Cfg.HTTPServer.Port, "http-port", 8080, "HTTP server port")
	flag.StringVar(&Cfg.HTTPServer.TLS.Crt, "http-tls-cert", "", "TLS certificate for HTTP server")
	flag.StringVar(&Cfg.HTTPServer.TLS.Key, "http-tls-key", "", "TLS key for HTTP server")
	flag.BoolVar(&Cfg.HTTPServer.AllowAnonymous, "http-allow-anonymous", false, "Allow anonymous access to HTTP server")
	flag.Parse()
	loadConfigFromEnv()
	ll, err := log.ParseLevel(Cfg.LogLevel)
	if err != nil {
		ll = log.InfoLevel
	}
	log.SetLevel(ll)
	metrics.PromNamespace = Cfg.Metrics.Namespace
	if rerr := metrics.RegisterMetrics(); rerr != nil {
		l.WithError(rerr).Fatal("error registering metrics")
	}
	go metrics.StartExporter(Cfg.Metrics.Port)
	smtp.AllowAnonymous = Cfg.SMTP.AllowAnonymousAuth
	smtp.Relay = &smtp.RelayConfig{
		Host:                  Cfg.Relay.Addr,
		Port:                  Cfg.Relay.Port,
		From:                  Cfg.Relay.From,
		User:                  Cfg.Relay.User,
		Pass:                  Cfg.Relay.Pass,
		TLSEnable:             Cfg.Relay.TLS.Enable,
		TLSCa:                 Cfg.Relay.TLS.Ca,
		TLSCrt:                Cfg.Relay.TLS.Crt,
		TLSKey:                Cfg.Relay.TLS.Key,
		TLSInsecureSkipVerify: Cfg.Relay.TLS.InsecureSkipVerify,
		UTF8:                  Cfg.SMTP.EnableSMTPUTF8,
		RequireTLS:            Cfg.SMTP.EnableREQUIRETLS,
		BinaryMime:            Cfg.SMTP.EnableBINARYMIME,
	}
	numActiveListeners := 0
	if Cfg.SMTP.EnablePlain {
		go func() {
			if err := smtp.Start(
				Cfg.SMTP.Addr,
				Cfg.SMTP.Port,
				Cfg.SMTP.TLS.CaCert,
				Cfg.SMTP.TLS.Cert,
				Cfg.SMTP.TLS.Key,
				Cfg.SMTP.AllowInsecureAuth,
				Cfg.SMTP.EnableSMTPUTF8,
				Cfg.SMTP.EnableREQUIRETLS,
				Cfg.SMTP.EnableBINARYMIME,
			); err != nil {
				l.WithError(err).Fatal("smtp server failed")
			}
		}()
		numActiveListeners++
	}
	if Cfg.SMTP.TLS.Enable {
		go func() {
			if err := smtp.Start(
				Cfg.SMTP.Addr,
				Cfg.SMTP.TLS.Port,
				Cfg.SMTP.TLS.CaCert,
				Cfg.SMTP.TLS.Cert,
				Cfg.SMTP.TLS.Key,
				Cfg.SMTP.AllowInsecureAuth,
				Cfg.SMTP.EnableSMTPUTF8,
				Cfg.SMTP.EnableREQUIRETLS,
				Cfg.SMTP.EnableBINARYMIME,
			); err != nil {
				l.WithError(err).Fatal("smtp server failed")
			}
		}()
		numActiveListeners++
	}
	if Cfg.HTTPServer.Enable {
		server.AllowAnonymous = Cfg.HTTPServer.AllowAnonymous
		go func() {
			if err := server.Start(
				Cfg.HTTPServer.Port,
				Cfg.HTTPServer.TLS.Crt,
				Cfg.HTTPServer.TLS.Key,
			); err != nil {
				l.WithError(err).Fatal("http server failed")
			}
		}()
		numActiveListeners++
	}
	if numActiveListeners == 0 {
		l.Warn("no listeners enabled")
	}
	if Cfg.ProviderConfig.Service != "" {
		go auth.HotLoadProviderRemote(Cfg.ProviderConfig.Service)
	} else if Cfg.ProviderConfig.File != "" {
		go auth.HotLoadProviderConfigFile(Cfg.ProviderConfig.File)
	}
	select {}
}
