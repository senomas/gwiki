package web

import "context"

type contextKey int

const userKey contextKey = iota

type User struct {
	Name string
}

func CurrentUser(ctx context.Context) (User, bool) {
	value := ctx.Value(userKey)
	user, ok := value.(User)
	return user, ok
}
