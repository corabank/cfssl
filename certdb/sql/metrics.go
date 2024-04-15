package sql

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// meter can be a global/package variable.
var meter = otel.Meter("cfssl/certdb")

var queryHistogram, _ = meter.Int64Histogram(
	"query_timing",
	metric.WithDescription("The time it takes to query the database"),
	metric.WithUnit("milliseconds"),
)

func mensureQueryTime(operation string) func() {
	start := time.Now()
	return func() {
		elapsed := time.Since(start)

		queryHistogram.Record(
			context.Background(),
			elapsed.Milliseconds(),
			metric.WithAttributes(attribute.String("operation", operation)),
		)
	}
}
