package controllers

import (
	"github.com/BenMz/base_api/app"
    beego "github.com/beego/beego/v2/server/web"
)

type NestPreparer interface {
    NestPrepare()
}

type ApiController struct {
    beego.Controller
}

func (c *ApiController) Prepare() {
	if isValid, user_id, message := app.ParseJWT(c.Ctx); isValid {
		c.Data["logged_user"] = user_id;
        if a, ok := c.AppController.(NestPreparer); ok {
                a.NestPrepare()
        }
	} else {
	    response := &app.AuthResponse {
	        Success: 0,
	        Message: message,
	    }
	    c.Data["json"] = response;
        c.Ctx.Output.SetStatus(401)
	    c.ServeJSON();
	    return ;
	}
}