package web

import "context"

type contextKey int

const userKey contextKey = iota

type User struct {
	Name          string
	Authenticated bool
}

func WithUser(ctx context.Context, user User) context.Context {
	return context.WithValue(ctx, userKey, user)
}

func CurrentUser(ctx context.Context) (User, bool) {
	value := ctx.Value(userKey)
	user, ok := value.(User)
	return user, ok
}

func IsAuthenticated(ctx context.Context) bool {
	user, ok := CurrentUser(ctx)
	return ok && user.Authenticated
}
