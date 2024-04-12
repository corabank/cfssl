package dbmetrics

import (
	"database/sql"

	"github.com/prometheus/client_golang/prometheus"
)

// Statser is an interface that wraps the Stats method.
type Statser interface {
	Stats() sql.DBStats
}

// StatsCollector implements the prometheus.Collector interface.
type StatsCollector struct {
	s Statser

	// descriptions of exported metrics
	maxOpenDesc           *prometheus.Desc
	openDesc              *prometheus.Desc
	inUseDesc             *prometheus.Desc
	idleDesc              *prometheus.Desc
	waitedForDesc         *prometheus.Desc
	blockedSecondsDesc    *prometheus.Desc
	closedMaxIdleDesc     *prometheus.Desc
	closedMaxLifetimeDesc *prometheus.Desc
}

func NewStatsCollector(s Statser, dbName string) *StatsCollector {
	labels := prometheus.Labels{"db_name": dbName}
	return &StatsCollector{
		s: s,
		maxOpenDesc: prometheus.NewDesc(
			"db_max_open_connections",
			"Maximum number of open connections to the database",
			nil, labels,
		),
		openDesc: prometheus.NewDesc(
			"db_open_connections",
			"Number of established connections to the database",
			nil, labels,
		),
		inUseDesc: prometheus.NewDesc(
			"db_in_use_connections",
			"Number of connections currently in use",
			nil, labels,
		),
		idleDesc: prometheus.NewDesc(
			"db_idle_connections",
			"Number of idle connections",
			nil, labels,
		),
		waitedForDesc: prometheus.NewDesc(
			"db_connections_waited_for",
			"Total number of connections waited for",
			nil, labels,
		),
		blockedSecondsDesc: prometheus.NewDesc(
			"db_connections_blocked_seconds",
			"Total time blocked waiting for a new connection",
			nil, labels,
		),
		closedMaxIdleDesc: prometheus.NewDesc(
			"db_connections_closed_max_idle",
			"Total number of connections closed due to SetMaxIdleConns",
			nil, labels,
		),
		closedMaxLifetimeDesc: prometheus.NewDesc(
			"db_connections_closed_max_lifetime",
			"Total number of connections closed due to SetConnMaxLifetime",
			nil, labels,
		),
	}
}

// Describe implements the prometheus.Collector interface.
func (c StatsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.maxOpenDesc
	ch <- c.openDesc
	ch <- c.inUseDesc
	ch <- c.idleDesc
	ch <- c.waitedForDesc
	ch <- c.blockedSecondsDesc
	ch <- c.closedMaxIdleDesc
	ch <- c.closedMaxLifetimeDesc
}

// Collect implements the prometheus.Collector interface.
func (c StatsCollector) Collect(ch chan<- prometheus.Metric) {
	stats := c.s.Stats()

	ch <- prometheus.MustNewConstMetric(
		c.maxOpenDesc,
		prometheus.GaugeValue,
		float64(stats.MaxOpenConnections),
	)
	ch <- prometheus.MustNewConstMetric(
		c.openDesc,
		prometheus.GaugeValue,
		float64(stats.OpenConnections),
	)
	ch <- prometheus.MustNewConstMetric(
		c.inUseDesc,
		prometheus.GaugeValue,
		float64(stats.InUse),
	)
	ch <- prometheus.MustNewConstMetric(
		c.idleDesc,
		prometheus.GaugeValue,
		float64(stats.Idle),
	)
	ch <- prometheus.MustNewConstMetric(
		c.waitedForDesc,
		prometheus.CounterValue,
		float64(stats.WaitCount),
	)
	ch <- prometheus.MustNewConstMetric(
		c.blockedSecondsDesc,
		prometheus.CounterValue,
		stats.WaitDuration.Seconds(),
	)
	ch <- prometheus.MustNewConstMetric(
		c.closedMaxIdleDesc,
		prometheus.CounterValue,
		float64(stats.MaxIdleClosed),
	)
	ch <- prometheus.MustNewConstMetric(
		c.closedMaxLifetimeDesc,
		prometheus.CounterValue,
		float64(stats.MaxLifetimeClosed),
	)
}
