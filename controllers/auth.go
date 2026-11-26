package controllers

import (
    "github.com/BenMz/base_api/app"
    "github.com/BenMz/base_api/models"
    beego "github.com/beego/beego/v2/server/web"
    "time"
)

func init() {

}
type AuthController struct {
    beego.Controller
}

func (c *AuthController) Post() {
    username := c.GetString("username");
    password := c.GetString("password");

    // The plain text still decides during PR 5's transition (models/tokenlogin.go).
    _, dbToken, ok, err := models.MatchTokenLogin(username, password, models.ClassifyTokenSource(c.Ctx.Request))

    response := &app.AuthResponse {
        Success: 0,
        Message: "unknown_error",
    }

    if err != nil || !ok {
        response.Message = "Invalid username or password";
    } else {
        response.Success = 1;
        response.Message = "Success";
        user_id, _ := c.GetInt64("user_id") 
        tokenString, exp, _ := app.NewAuthToken(dbToken, user_id, time.Now())
        var responseUser *app.Auth = new(app.Auth);
        responseUser.Token = tokenString;
        responseUser.Expire_at = exp;
        response.Data  = responseUser;
    }

    c.Data["json"] = response;
    c.ServeJSON();
}
