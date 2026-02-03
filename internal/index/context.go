package index

import "context"

type contextKey int

const (
	visibilityFilterKey contextKey = iota
	accessFilterKey
)

type visibilityFilter struct {
	publicOnly bool
}

type accessFilter struct {
	userID   int
	ownerIDs []int
}

func WithPublicVisibility(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, visibilityFilterKey, visibilityFilter{publicOnly: true})
}

func WithAccessFilter(ctx context.Context, userID int, ownerIDs []int) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	filter := accessFilter{userID: userID, ownerIDs: ownerIDs}
	return context.WithValue(ctx, accessFilterKey, filter)
}

func publicOnly(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value := ctx.Value(visibilityFilterKey)
	filter, ok := value.(visibilityFilter)
	return ok && filter.publicOnly
}

func accessFilterFromContext(ctx context.Context) (accessFilter, bool) {
	if ctx == nil {
		return accessFilter{}, false
	}
	value := ctx.Value(accessFilterKey)
	filter, ok := value.(accessFilter)
	return filter, ok
}
