package authorization

import (
	"github.com/gin-gonic/gin"
	"github.com/xmdas-link/auth"
)

type Authorizer interface {
	GetUserNameFromContext(context interface{}) string
	GetUserRoleFromContext(context interface{}) string
	GetUserDomainFromContext(context interface{}) string
}

type DefaultGinAuthorize struct {
}

func (DefaultGinAuthorize) GetUserNameFromContext(ctx interface{}) string {
	if ctx, ok := ctx.(*gin.Context); ok {
		user := ctx.GetStringMapString(auth.CtxKeyAuthUser)
		if username, ok := user["user"]; ok {
			return username
		}
	}

	return ""
}

func (DefaultGinAuthorize) GetUserRoleFromContext(ctx interface{}) string {
	if ctx, ok := ctx.(*gin.Context); ok {
		userRole := ctx.GetString(auth.CtxKeyUserRole)
		return userRole
	}

	return ""
}

func (DefaultGinAuthorize) GetUserDomainFromContext(ctx interface{}) string {
	if ctx, ok := ctx.(*gin.Context); ok {
		user := ctx.GetStringMapString(auth.CtxKeyAuthUser)
		if domain, ok := user["domain"]; ok {
			return domain
		}
	}

	return ""
}
