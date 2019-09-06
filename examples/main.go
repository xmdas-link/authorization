package main

import (
	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
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

func main() {
	route := gin.Default()

	enforcer, _ = casbin.NewEnforcer("model.conf", "policy.csv")
	route.Use(authorization.NewAuthorizer(enforcer))

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
