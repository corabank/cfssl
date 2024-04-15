package otel

import (
	"os"

	"github.com/cloudflare/cfssl/log"
	"github.com/honeycombio/otel-config-go/otelconfig"
)

// Setup configures the OpenTelemetry.
func Setup(service string) func() {
	url := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if url == "" {
		log.Warning("No OTEL_EXPORTER_OTLP_ENDPOINT provided, OpenTelemetry will not be configured")
		return func() {}
	}

	shutdown, err := otelconfig.ConfigureOpenTelemetry(
		otelconfig.WithServiceName(service),
		otelconfig.WithExporterEndpoint(url),
		otelconfig.WithExporterProtocol(otelconfig.ProtocolHTTPProto),
		otelconfig.WithExporterInsecure(true),
		otelconfig.WithMetricsEnabled(true),
		otelconfig.WithTracesEnabled(false),
	)
	if err != nil {
		log.Warning("Failed to configure OpenTelemetry: %v", err)
		return func() {}
	}

	return shutdown
}
