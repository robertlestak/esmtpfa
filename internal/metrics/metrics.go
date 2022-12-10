package metrics

import (
	"fmt"
	"net/http"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	PromNamespace                 string
	AuthRequests                  *prometheus.CounterVec
	AuthSuccesses                 *prometheus.CounterVec
	AuthFailures                  *prometheus.CounterVec
	MessagesSent                  *prometheus.CounterVec
	FallbackAuthRequests          *prometheus.CounterVec
	BytesSent                     *prometheus.CounterVec
	BytesSentToAddress            *prometheus.CounterVec
	BytesSentFromAddress          *prometheus.CounterVec
	ConfiguredProviders           *prometheus.GaugeVec
	MailFromTo                    *prometheus.CounterVec
	UpstreamResponseTimeHistogram *prometheus.HistogramVec
)

func RegisterMetrics() error {
	l := log.WithFields(log.Fields{
		"module": "metrics",
		"action": "registerMetrics",
	})
	l.Debug("registering metrics")

	AuthRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: PromNamespace,
			Name:      "connections_total",
			Help:      "Total number of auth requests by provider and status",
		},
		[]string{"provider", "status"},
	)
	FallbackAuthRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: PromNamespace,
			Name:      "fallback_connections_total",
			Help:      "Total number of fallback auth requests by provider and status",
		},
		[]string{"provider", "status"},
	)
	AuthSuccesses = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: PromNamespace,
			Name:      "auth_successes_total",
			Help:      "Total number of auth success by provider",
		},
		[]string{"provider"},
	)
	AuthFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: PromNamespace,
			Name:      "auth_failures_total",
			Help:      "Total number of auth failure by provider",
		},
		[]string{"provider"},
	)
	BytesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: PromNamespace,
			Name:      "bytes_sent_total",
			Help:      "Total number of bytes sent by provider",
		},
		[]string{"provider"},
	)
	BytesSentFromAddress = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: PromNamespace,
			Name:      "bytes_sent_from_address_total",
			Help:      "Total number of bytes sent by provider",
		},
		[]string{"provider", "from"},
	)
	BytesSentToAddress = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: PromNamespace,
			Name:      "bytes_sent_to_address_total",
			Help:      "Total number of bytes sent by provider",
		},
		[]string{"provider", "to"},
	)
	MessagesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: PromNamespace,
			Name:      "messages_sent_total",
			Help:      "Total number of messages sent by provider",
		},
		[]string{"provider"},
	)
	ConfiguredProviders = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: PromNamespace,
			Name:      "configured_providers",
			Help:      "A gauge of configured providers",
		},
		[]string{"name", "domain", "domain_selection", "fallback", "type"},
	)
	MailFromTo = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: PromNamespace,
			Name:      "mail_from_to",
			Help:      "A counter of mail from to",
		},
		[]string{"from", "to", "status"},
	)
	UpstreamResponseTimeHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: PromNamespace,
		Name:      "smtp_server_request_duration_seconds",
		Help:      "Histogram of response time for proxied smtp server in seconds",
		Buckets:   []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 120, 180, 240, 300, 360, 420, 480, 540, 600},
	}, []string{"server", "status"})

	prometheus.MustRegister(
		AuthRequests,
		AuthSuccesses,
		AuthFailures,
		UpstreamResponseTimeHistogram,
		ConfiguredProviders,
		MailFromTo,
		BytesSent,
		MessagesSent,
		FallbackAuthRequests,
		BytesSentFromAddress,
		BytesSentToAddress,
	)
	return nil
}

// StartExporter starts the prometheus exporter to export
func StartExporter(port int) error {
	l := log.WithFields(log.Fields{
		"component": "metrics",
		"action":    "start",
		"port":      port,
	})
	l.Debug("starting metrics exporter")
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	l.Debugf("starting metrics exporter on port %s", port)
	http.ListenAndServe(":"+strconv.Itoa(port), nil)
	return nil
}
