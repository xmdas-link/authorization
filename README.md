# authorization
基于casbin的gin权限验证中间件，定义好模型与策略文件后，可快速用于gin框架。
## 用法
```go
import (
    "github.com/xmdas-link/authorization"
    gormadapter "github.com/casbin/gorm-adapter/v2"
)

route := gin.Default()

// 从策略文件加载策略规则
enforcer, _ = casbin.NewEnforcer("model.conf", "policy.csv")
route.Use(authorization.NewAuthorizer(enforcer))

// 从数据库加载策略规则，动态加载更新策略
db, _ := gorm.Open("mysql", "root:123456@tcp(127.0.0.1:33306)/approval?parseTime=true&loc=Local")
adapter, _ := gormadapter.NewAdapterByDB(db)
enforcer, _ = casbin.NewEnforcer("model.conf", adapter)
// dynamic add policy
enforcer.AddPolicy("alice", "/school/list", "(GET)|(POST)", "allow")
enforcer.AddPolicy("user", "/school/add", "(GET)|(POST)", "allow")
// dynamic add group relationship
enforcer.AddGroupingPolicy("alice", "user")
enforcer.AddGroupingPolicy("bob", "user")
// reload policy from file/db
enforcer.LoadPolicy()
```
## 模型文件
```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.sub, p.sub) && keyMatch2(r.obj, p.obj) && regexMatch(r.act, p.act)
```
## 策略文件
```csv
p, user, /school/list, (GET)|(POST), allow
p, admin, /school/add, (GET)|(POST), allow
p, alice, /person/list, (GET)|(POST), allow
p, alice, /person/add, (GET)|(POST), allow
p, bob, /school/list, (GET)|(POST), deny

g, alice, admin
g, bob, admin
g, foo, user
g, admin, user
```
