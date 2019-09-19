package authorization

import (
	"log"
	"net/http"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	"github.com/xmdas-link/auth"
)

func NewAuthorizer(enforcer *casbin.Enforcer, args ...bool) gin.HandlerFunc {
	var withDomains = false
	if len(args) > 0 {
		withDomains = args[0]
	}
	authorizer := &BasicAuthorizer{enforcer, withDomains}

	return func(context *gin.Context) {
		// apply authorizer
		log.Printf("casbin middleware. ip: %v, fullpath: %v, uri: %v", context.ClientIP(), context.Request.URL.Path, context.Request.RequestURI)

		if !authorizer.CheckPermission(context) {
			authorizer.RequirePermission(context)
		}
	}
}

type BasicAuthorizer struct {
	enforcer    *casbin.Enforcer
	withDomains bool
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

func (authorize *BasicAuthorizer) GetUserDomain(ctx *gin.Context) string {
	user := ctx.GetStringMapString(auth.CtxKeyAuthUser)
	if domain, ok := user["domain"]; ok {
		return domain
	}

	return ""
}

func (authorize *BasicAuthorizer) RequirePermission(ctx *gin.Context) {
	ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"code":    0,
		"message": "没有权限",
	})
}

func (authorize *BasicAuthorizer) CheckPermission(ctx *gin.Context) bool {
	sub := authorize.GetUserName(ctx)
	role := authorize.GetUserRole(ctx)
	domain := authorize.GetUserDomain(ctx)
	obj := ctx.Request.URL.Path
	act := ctx.Request.Method

	if authorize.withDomains {
		return checkDomainPermission(authorize, sub, role, domain, obj, act)
	} else {
		return checkPermission(authorize, sub, role, obj, act)
	}
}

func checkPermission(authorize *BasicAuthorizer, sub, role, obj, act string) bool {
	allowed, _ := authorize.enforcer.Enforce(sub, obj, act)
	log.Printf("casbin check permission, sub:%v, obj:%v, act:%v, allowed:%v", sub, obj, act, allowed)
	if !allowed { // 用户没有权限，判断角色权限
		allowed, _ = authorize.enforcer.Enforce(role, obj, act)
		log.Printf("casbin check permission, role:%v, obj:%v, act:%v, allowed:%v", role, obj, act, allowed)
	}

	return allowed
}

func checkDomainPermission(authorize *BasicAuthorizer, sub, role, domain, obj, act string) bool {
	allowed, _ := authorize.enforcer.Enforce(sub, domain, obj, act)
	log.Printf("casbin check permission, sub:%v, domain:%v, obj:%v, act:%v, allowed:%v", sub, domain, obj, act, allowed)
	if !allowed { // 用户没有权限，判断角色权限
		allowed, _ = authorize.enforcer.Enforce(role, domain, obj, act)
		log.Printf("casbin check permission, role:%v, domain:%v, obj:%v, act:%v, allowed:%v", role, domain, obj, act, allowed)
	}

	return allowed
}
