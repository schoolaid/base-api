package models

import (
	"github.com/beego/beego/v2/client/orm"
)

// ExternalUser is an integrator credential. The plain-text password is deliberately not mapped
// (Notion 999, PR 5): only the token route reads it (MatchTokenLogin), so the contract step can
// drop the column without breaking GetExternalUser.
type ExternalUser struct {
	Id         int64  `orm:"auto"`
	Name      string `orm:"size(30)"`
	Username   string `orm:"size(50)"`
	Token   string `orm:"size(100)"`
}

type ExternalUserSchool struct {
	SchoolId         int64  `orm:"auto"`
	ExternalUserId         int64  
}

func init() {
	orm.RegisterModel(new(ExternalUser))
}
func GetExternalUser(token string) (v *ExternalUser, err error) {
	o := orm.NewOrm()
	v = &ExternalUser{Token: token}
	if err = o.Read(v, "Token"); err == nil {
		return v, nil
	}
	return nil, err
}

func GetExternalUserSchool(id int64) (v *ExternalUserSchool, err error) {
	o := orm.NewOrm()
	v = &ExternalUserSchool{ExternalUserId: id}
	if err = o.Read(v, "ExternalUserId"); err == nil {
		return v, nil
	}
	return nil, err
}