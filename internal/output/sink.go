package output

import "context"

// ChunkSink receives a sanitized output chunk tagged with its stream
// ("stdout" or "stderr") as a command runs. The MCP layer attaches one to the
// exec context to stream output live; the exec sinks forward each chunk to it.
type ChunkSink func(stream string, chunk []byte)

type sinkKeyType struct{}

var sinkKey sinkKeyType

// WithSink attaches a live-output sink to ctx (a no-op if s is nil, so the
// non-streaming path stays unchanged).
func WithSink(ctx context.Context, s ChunkSink) context.Context {
	if s == nil {
		return ctx
	}
	return context.WithValue(ctx, sinkKey, s)
}

// SinkFor returns a StreamWriter callback that forwards chunks of the named
// stream to the ctx sink, or nil if no sink is attached (no live streaming).
func SinkFor(ctx context.Context, stream string) func([]byte) {
	s, ok := ctx.Value(sinkKey).(ChunkSink)
	if !ok || s == nil {
		return nil
	}
	return func(chunk []byte) { s(stream, chunk) }
}
