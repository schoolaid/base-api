package main

import (
	_ "github.com/BenMz/base_api/routers"
	beego "github.com/beego/beego/v2/server/web"
)

func main() {
	beego.Run()
}
