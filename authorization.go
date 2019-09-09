package authorization

import (
	"log"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	"github.com/xmdas-link/auth"
)

func NewAuthorizer(enforcer *casbin.Enforcer) gin.HandlerFunc {
	authorizer := &BasicAuthorizer{enforcer}

	return func(context *gin.Context) {
		// apply authorizer
		log.Printf("casbin middleware. ip: %v, fullpath: %v, uri: %v", context.ClientIP(), context.Request.URL.Path, context.Request.RequestURI)

		if !authorizer.CheckPermission(context) {
			authorizer.RequirePermission(context)
		}
	}
}

type BasicAuthorizer struct {
	enforcer *casbin.Enforcer
}

func (authorize *BasicAuthorizer) GetUserName(ctx *gin.Context) string {
	user := ctx.GetStringMapString(auth.CtxKeyAuthUser)
	if username, ok := user["name"]; ok {
		return username
	}

	return ""
}

func (authorize *BasicAuthorizer) GetUserRole(ctx *gin.Context) string {
	userRole := ctx.GetString(auth.CtxKeyUserRole)
	return userRole
}

func (authorize *BasicAuthorizer) RequirePermission(ctx *gin.Context) {
	ctx.AbortWithStatus(403)
}

func (authorize *BasicAuthorizer) CheckPermission(ctx *gin.Context) bool {
	obj := ctx.Request.URL.Path
	sub := authorize.GetUserName(ctx)
	act := ctx.Request.Method

	allowed, _ := authorize.enforcer.Enforce(sub, obj, act)
	return allowed
}
