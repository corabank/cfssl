package sql

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var queryHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
	Name: "go.sql.query_timing",
	Help: "Histogram of query timings in milliseconds",
}, []string{"operation"})

func registerMetrics() {
	prometheus.MustRegister(queryHistogram)
}

func mensureQueryTime(operation string) func() {
	start := time.Now()
	return func() {
		queryHistogram.WithLabelValues(operation).Observe(float64(time.Since(start).Milliseconds()))
	}
}
