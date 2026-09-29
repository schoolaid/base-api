package app

import(
	beego "github.com/beego/beego/v2/server/web"
)



var (
	Secret_key []byte
)

func init(){
	secretKey, _ := beego.AppConfig.String("secretKey")
	Secret_key =  []byte(secretKey);
}
