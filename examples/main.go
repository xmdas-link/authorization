package main

import (
	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"github.com/xmdas-link/authorization"
)

type User struct {
	UserName   string  `json:"user_name"`
	UserPwd    string  `json:"-"`
	UserSalary float64 `json:"user_salary, omitempty"`
	UserAge    int     `json:"user_age"`
	UserMobile string  `json:"user_mobile"`

	Profile Profile `json:"profile"`
}

type Profile struct {
	ID    int    `json:"-"`
	Grade int    `json:"grade"`
	Photo string `json:"photo"`
}

type School struct {
	SchoolId   int    `json:"school_id"`
	SchoolName string `json:"school_name"`
	SchoolCode string `json:"school_code"`
}

/**
权限中间件测试：
http://127.0.0.1:8080/school/list?mobile=123&username=alice
http://127.0.0.1:8080/school/list?mobile=123&username=bob
http://127.0.0.1:8080/school/list?mobile=123&username=foo
*/

var enforcer *casbin.Enforcer

type queryAuthorizer struct {
}

func (queryAuthorizer) GetUserNameFromContext(ctx interface{}) string {
	if ctx, ok := ctx.(*gin.Context); ok {
		return ctx.Query("username")
	}

	return ""
}

func (queryAuthorizer) GetUserRoleFromContext(ctx interface{}) string {
	if ctx, ok := ctx.(*gin.Context); ok {
		return ctx.Query("role")
	}

	return ""
}

func (queryAuthorizer) GetUserDomainFromContext(ctx interface{}) string {
	if ctx, ok := ctx.(*gin.Context); ok {
		return ctx.Query("domain")
	}

	return ""
}

func main() {
	route := gin.Default()

	//// load policy from db
	//db, _ := gorm.Open("mysql", "root:123456@tcp(127.0.0.1:33306)/approval?parseTime=true&loc=Local")
	//db.LogMode(true)
	//adapter, _ := gormadapter.NewAdapterByDB(db)
	//enforcer, _ = casbin.NewEnforcer("model.conf", adapter)
	//// dynamic add policy
	//enforcer.AddPolicy("alice", "/school/list", "(GET)|(POST)", "allow")
	//enforcer.AddPolicy("user", "/school/add", "(GET)|(POST)", "allow")
	//// dynamic add group relationship
	//enforcer.AddGroupingPolicy("alice", "user")
	//enforcer.AddGroupingPolicy("bob", "user")

	// load policy from file
	//enforcer, _ = casbin.NewEnforcer("model.conf", "policy.csv")
	//route.Use(authorization.NewAuthorizer(enforcer))

	// load domain policy from file
	enforcer, _ = casbin.NewEnforcer("model_domain.conf", "policy_domain.csv")
	//route.Use(authorization.NewAuthorizer(enforcer, nil, true))
	route.Use(authorization.NewAuthorizer(enforcer, queryAuthorizer{}, true))

	route.GET("/", helloHandler)
	route.GET("/school/list", getSchool)
	route.GET("/school/add", postSchool)
	route.GET("/person/list", getPerson)
	route.POST("/person/add", postPerson)

	route.Run()
}

func helloHandler(ctx *gin.Context) {
	ctx.JSON(200, gin.H{
		"message": "hello",
	})
}

func getSchool(ctx *gin.Context) {
	user := User{
		UserName:   "test",
		UserPwd:    "123456",
		UserSalary: 342342,
		UserAge:    26,
		UserMobile: ctx.DefaultQuery("mobile", "123456789"),
		Profile: Profile{
			ID:    4,
			Grade: 5,
			Photo: "nnnnnnn",
		},
	}

	ctx.JSON(200, gin.H{
		"data": user,
	})
}

func postSchool(ctx *gin.Context) {
	school := School{
		SchoolId:   1,
		SchoolName: "学校",
		SchoolCode: "codetest",
	}

	// reload policy from file/db
	enforcer.LoadPolicy()

	ctx.JSON(200, gin.H{
		"data": school,
	})
}
func getPerson(ctx *gin.Context) {
	ctx.JSON(200, gin.H{
		"message": "getPerson",
	})
}
func postPerson(ctx *gin.Context) {
	ctx.JSON(200, gin.H{
		"message": "postPerson",
	})
}
