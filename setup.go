package otelsetup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutlog"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	lg "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	mt "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	tr "go.opentelemetry.io/otel/trace"
)

var (
	// Tracer is used to initialise traces and spans
	// Do not use until after SetupOtel has been called
	Tracer tr.Tracer
	// Metrics is used to set up metrics instances
	// Do not use until after SetupOtel has been called
	Metrics mt.Meter
	// Log is used for logging.
	// You probably want to use the LogXxxx functions
	// instead of calling this directly
	Log lg.Logger
)

// LogTrace writes a trace level log to the OTel Log Exporter
//
// Do not use until after SetupOtel has been called
func LogTrace(ctx context.Context, message string) {
	writeLog(ctx, lg.SeverityTrace, message)
}

// LogDebug writes a debug level log to the OTel Log Exporter
//
// Do not use until after SetupOtel has been called
func LogDebug(ctx context.Context, message string) {
	writeLog(ctx, lg.SeverityDebug, message)
}

// LogInfo writes an info level log to the OTel Log Exporter
//
// Do not use until after SetupOtel has been called
func LogInfo(ctx context.Context, message string) {
	writeLog(ctx, lg.SeverityInfo, message)
}

// LogWarn writes a warning level log to the OTel Log Exporter
//
// Do not use until after SetupOtel has been called
func LogWarn(ctx context.Context, message string) {
	writeLog(ctx, lg.SeverityWarn, message)
}

// LogError writes an error level log to the OTel Log Exporter
//
// Do not use until after SetupOtel has been called
func LogError(ctx context.Context, message string) {
	writeLog(ctx, lg.SeverityError, message)
}

// LogFatal writes a fatal level log to the OTel Log Exporter
//
// Do not use until after SetupOtel has been called
func LogFatal(ctx context.Context, message string) {
	writeLog(ctx, lg.SeverityFatal, message)
}

func writeLog(ctx context.Context, level lg.Severity, message string) {
	var logMessage = lg.Record{}
	logMessage.SetBody(lg.StringValue(message))
	logMessage.SetSeverity(level)
	logMessage.SetSeverityText(level.String())
	logMessage.SetTimestamp(time.Now())

	Log.Emit(ctx, logMessage)
}

// SetupOTelSDK bootstraps the OpenTelemetry pipeline.
// If it does not return an error, make sure to call shutdown for proper cleanup.
func SetupOTel(ctx context.Context, appName ...string) (shutdown func(context.Context) error, err error) {
	var app = appName[0]
	if app == "" {
		app = os.Args[0]
	}

	var res, resError = resource.New(
		ctx,
		resource.WithAttributes(
			attribute.String("service.name", app),
			attribute.String("library.language", "go"),
		),
	)
	if resError != nil {
		fmt.Fprintln(os.Stderr, "Could not set resources: ", resError.Error())
	}

	var shutdownFuncs []func(context.Context) error

	// shutdown calls cleanup functions registered via shutdownFuncs.
	// The errors from the calls are joined.
	// Each registered cleanup will be invoked once.
	shutdown = func(ctx context.Context) error {
		var err error
		for _, fn := range shutdownFuncs {
			err = errors.Join(err, fn(ctx))
		}
		shutdownFuncs = nil
		return err
	}

	// handleErr calls shutdown for cleanup and makes sure that all errors are returned.
	handleErr := func(inErr error) {
		err = errors.Join(inErr, shutdown(ctx))
	}

	// Set up propagator.
	prop := newPropagator()
	otel.SetTextMapPropagator(prop)

	// Set up trace provider.
	tracerProvider, err := newTracerProvider(*res)
	if err != nil {
		handleErr(err)
		return
	}
	shutdownFuncs = append(shutdownFuncs, tracerProvider.Shutdown)
	otel.SetTracerProvider(tracerProvider)

	// Set up meter provider.
	meterProvider, err := newMeterProvider(*res)
	if err != nil {
		handleErr(err)
		return
	}
	shutdownFuncs = append(shutdownFuncs, meterProvider.Shutdown)
	otel.SetMeterProvider(meterProvider)

	// Set up logger provider.
	loggerProvider, err := newLoggerProvider(*res)
	if err != nil {
		handleErr(err)
		return
	}
	shutdownFuncs = append(shutdownFuncs, loggerProvider.Shutdown)
	global.SetLoggerProvider(loggerProvider)

	Tracer = tracerProvider.Tracer(app)
	Metrics = meterProvider.Meter(app)
	Log = loggerProvider.Logger(app)

	return
}

func newPropagator() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
}

func newTracerProvider(res resource.Resource) (*trace.TracerProvider, error) {
	_, otelAvailable := os.LookupEnv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if otelAvailable {
		return newOtlpTracerProvider(res)
	} else {
		return newStdOutTracerProvider(res)
	}
}

func newMeterProvider(res resource.Resource) (*metric.MeterProvider, error) {
	_, otelAvailable := os.LookupEnv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if otelAvailable {
		return newOtlpMeterProvider(res)
	} else {
		return newStdOutMeterProvider(res)
	}
}

func newLoggerProvider(res resource.Resource) (*log.LoggerProvider, error) {
	_, otelAvailable := os.LookupEnv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if otelAvailable {
		return newOtlpLoggerProvider(res)
	} else {
		return newStdOutLoggerProvider(res)
	}
}

func newStdOutTracerProvider(res resource.Resource) (*trace.TracerProvider, error) {
	traceExporter, err := stdouttrace.New(
		stdouttrace.WithPrettyPrint(),
	)
	if err != nil {
		return nil, err
	}

	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(&res),
		trace.WithBatcher(traceExporter,
			// Default is 5s. Set to 1s for demonstrative purposes.
			trace.WithBatchTimeout(time.Second)),
	)
	return tracerProvider, nil
}

func newStdOutMeterProvider(res resource.Resource) (*metric.MeterProvider, error) {
	metricExporter, err := stdoutmetric.New(
		stdoutmetric.WithPrettyPrint(),
	)
	if err != nil {
		return nil, err
	}

	meterProvider := metric.NewMeterProvider(
		metric.WithResource(&res),
		metric.WithReader(metric.NewPeriodicReader(metricExporter,
			// Default is 1m. Set to 3s for demonstrative purposes.
			metric.WithInterval(3*time.Second))),
	)
	return meterProvider, nil
}

func newStdOutLoggerProvider(res resource.Resource) (*log.LoggerProvider, error) {
	logExporter, err := stdoutlog.New(
		stdoutlog.WithPrettyPrint(),
	)
	if err != nil {
		return nil, err
	}

	loggerProvider := log.NewLoggerProvider(
		log.WithResource(&res),
		log.WithProcessor(log.NewBatchProcessor(logExporter)),
	)
	return loggerProvider, nil
}

func newOtlpTracerProvider(res resource.Resource) (*trace.TracerProvider, error) {
	traceExporter, err := otlptracehttp.New(context.Background())
	if err != nil {
		return nil, err
	}

	tracerProvider := trace.NewTracerProvider(
		trace.WithResource(&res),
		trace.WithBatcher(traceExporter,
			// Default is 5s. Set to 1s for demonstrative purposes.
			trace.WithBatchTimeout(time.Second)),
	)
	return tracerProvider, nil
}

func newOtlpMeterProvider(res resource.Resource) (*metric.MeterProvider, error) {
	metricExporter, err := otlpmetrichttp.New(context.Background())
	if err != nil {
		return nil, err
	}

	meterProvider := metric.NewMeterProvider(
		metric.WithResource(&res),
		metric.WithReader(metric.NewPeriodicReader(metricExporter,
			// Default is 1m. Set to 3s for demonstrative purposes.
			metric.WithInterval(3*time.Second))),
	)
	return meterProvider, nil
}

func newOtlpLoggerProvider(res resource.Resource) (*log.LoggerProvider, error) {
	logExporter, err := otlploghttp.New(context.Background())
	if err != nil {
		return nil, err
	}

	loggerProvider := log.NewLoggerProvider(
		log.WithResource(&res),
		log.WithProcessor(log.NewBatchProcessor(logExporter)),
	)
	return loggerProvider, nil
}
