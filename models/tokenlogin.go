package models

import (
	"crypto/subtle"
	"errors"
	"strings"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/core/logs"
	beego "github.com/beego/beego/v2/server/web"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

// MatchTokenLogin decides a POST /token login (Notion 999, PR 5's transition).
//
// ⚠️ THE PLAIN TEXT STILL DECIDES, compared by MySQL exactly as before (utf8mb3_general_ci:
// case, trailing spaces and accents are ignored), as in external-api: support changes a password
// by editing that column, and a hash of the old one must not keep it working. password_hash
// decides only in the contract step, when the plain-text column goes.
//
// Until then every successful login writes ONE line, so the contract step can see, per credential
// and per service, when the hash can decide alone (never a value; silence never means safe):
//
//	token login: external_user=<id> app=<appname> match=exact|collation hash_accepts=yes|no|absent|unknown
//
// match=collation: MySQL accepted what an exact compare refuses. hash_accepts is password_hash's
// verdict on the SENT password (no: stale or collation-only; absent: none stored; unknown: no
// password_hash column, or a failed read). A clean login (exact, yes) is Info, anything else Warn.
//
// ⚠️ A BLANKED PLAIN TEXT LOGS NOTHING IN (empty, or only spaces, which PAD SPACE compares equal
// to the empty password): blanking the column disables a credential. The refusal is logged.
//
// ok is false for a wrong or unknown username or password; err is a failed read.
func MatchTokenLogin(username, password string) (id int64, token string, ok bool, err error) {
	var rows []struct {
		Id       int64
		Token    string
		Password string
	}
	o := orm.NewOrm()
	if _, err := o.Raw("SELECT id, token, password FROM external_user WHERE username = ? AND password = ?", username, password).QueryRows(&rows); err != nil {
		return 0, "", false, err
	}
	if len(rows) != 1 {
		return 0, "", false, nil
	}
	row := rows[0]
	app := appName()
	if strings.TrimRight(row.Password, " ") == "" {
		logs.Warn("token login refused: external_user=%d app=%s: blanked plain text", row.Id, app)
		return 0, "", false, nil
	}
	match := "exact"
	if subtle.ConstantTimeCompare([]byte(row.Password), []byte(password)) != 1 {
		match = "collation"
	}
	hashAccepts := hashVerdict(o, row.Id, password, app)
	line := "token login: external_user=%d app=%s match=%s hash_accepts=%s"
	if match == "exact" && hashAccepts == "yes" {
		logs.Info(line, row.Id, app, match, hashAccepts)
	} else {
		logs.Warn(line, row.Id, app, match, hashAccepts)
	}
	return row.Id, row.Token, true, nil
}

// hashVerdict is what password_hash would say about the sent password: "yes", "no", "absent"
// (none stored) or "unknown" (no password_hash column: 1054; or a failed read, which logs).
func hashVerdict(o orm.Ormer, id int64, password, app string) string {
	var hashes []*string
	if _, err := o.Raw("SELECT password_hash FROM external_user WHERE id = ?", id).QueryRows(&hashes); err != nil {
		var me *mysql.MySQLError
		if !errors.As(err, &me) || me.Number != 1054 {
			logs.Warn("token login: password hash not read: external_user=%d app=%s: %v", id, app, err)
		}
		return "unknown"
	}
	if len(hashes) != 1 || hashes[0] == nil || *hashes[0] == "" {
		return "absent"
	}
	if bcrypt.CompareHashAndPassword([]byte(*hashes[0]), []byte(password)) != nil {
		return "no"
	}
	return "yes"
}

// appName names the service in the transition line (each of positions-api, schoolaid-api and
// menu-api imports this route), so the window can be checked per service.
func appName() string {
	if name, err := beego.AppConfig.String("appname"); err == nil && name != "" {
		return name
	}
	return "unknown"
}
