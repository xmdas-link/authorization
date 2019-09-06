package authorization

import (
	"log"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
)

func NewAuthorizer(enforcer *casbin.Enforcer) gin.HandlerFunc {
	auth := &BasicAuthorizer{enforcer}

	return func(context *gin.Context) {
		// apply auth
		log.Printf("casbin middleware. ip: %v, fullpath: %v, uri: %v", context.ClientIP(), context.Request.URL.Path, context.Request.RequestURI)

		if !auth.CheckPermission(context) {
			auth.RequirePermission(context)
		}
	}
}

type BasicAuthorizer struct {
	enforcer *casbin.Enforcer
}

func (auth *BasicAuthorizer) GetUserName(ctx *gin.Context) string {
	// TODO get user name from gin.context
	return ctx.DefaultQuery("username", "")
}

func (auth *BasicAuthorizer) GetUserRole(ctx *gin.Context) string {
	// TODO get user role from gin.context
	return ctx.DefaultQuery("rolename", "admin")
}

func (auth *BasicAuthorizer) RequirePermission(ctx *gin.Context) {
	ctx.AbortWithStatus(403)
}

func (auth *BasicAuthorizer) CheckPermission(ctx *gin.Context) bool {
	obj := ctx.Request.URL.Path
	sub := auth.GetUserName(ctx)
	act := ctx.Request.Method

	allowed, _ := auth.enforcer.Enforce(sub, obj, act)
	return allowed
}
