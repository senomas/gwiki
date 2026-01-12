package index

import "context"

type contextKey int

const visibilityFilterKey contextKey = iota

type visibilityFilter struct {
	publicOnly bool
}

func WithPublicVisibility(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, visibilityFilterKey, visibilityFilter{publicOnly: true})
}

func publicOnly(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value := ctx.Value(visibilityFilterKey)
	filter, ok := value.(visibilityFilter)
	return ok && filter.publicOnly
}
