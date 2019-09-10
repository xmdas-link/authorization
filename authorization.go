package authorization

import (
	"log"
	"net/http"

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
	if username, ok := user["user"]; ok {
		return username
	}

	return ""
}

func (authorize *BasicAuthorizer) GetUserRole(ctx *gin.Context) string {
	userRole := ctx.GetString(auth.CtxKeyUserRole)
	return userRole
}

func (authorize *BasicAuthorizer) RequirePermission(ctx *gin.Context) {
	ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"code":    0,
		"message": "没有权限",
	})
}

func (authorize *BasicAuthorizer) CheckPermission(ctx *gin.Context) bool {
	sub := authorize.GetUserName(ctx)
	sub2 := authorize.GetUserRole(ctx)
	obj := ctx.Request.URL.Path
	act := ctx.Request.Method

	allowed, _ := authorize.enforcer.Enforce(sub, obj, act)
	log.Printf("casbin check permission, sub:%v, obj:%v, act:%v, allowed:%v", sub, obj, act, allowed)
	if !allowed { // 用户没有权限，判断角色权限
		allowed, _ = authorize.enforcer.Enforce(sub2, obj, act)
		log.Printf("casbin check permission, sub2:%v, obj:%v, act:%v, allowed:%v", sub2, obj, act, allowed)
	}

	return allowed
}
