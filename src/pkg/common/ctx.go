package common

import "context"

type ctxKey int

const (
	ctxKeyRequestID ctxKey = iota
	cInstanceID
	ctxKeyUserInfo
)

func WithContext(ctx context.Context, info *UserInfo) context.Context {
	return context.WithValue(ctx, ctxKeyUserInfo, info)
}

func FromContext(ctx context.Context) (*UserInfo, bool) {
	info, ok := ctx.Value(ctxKeyUserInfo).(*UserInfo)
	return info, ok
}

func MustFromContext(ctx context.Context) *UserInfo {
	info, ok := FromContext(ctx)
	if !ok {
		panic("user info not found in context")
	}
	return info
}

type UserInfo struct {
	InstanceID string
	DomainID   string
	DomainName string
	UserID     string
	Account    string
}
