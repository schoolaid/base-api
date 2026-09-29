package app

import (
	beego "github.com/beego/beego/v2/server/web"
	"github.com/beego/beego/v2/client/orm"
	_ "github.com/go-sql-driver/mysql"
)

func init(){
	dbUrl, _ := beego.AppConfig.String(beego.BConfig.RunMode+"::db")
    orm.RegisterDriver("mysql", orm.DRMySQL)
    orm.RegisterDataBase("default", "mysql", dbUrl)
    orm.MaxIdleConnections(60)
}