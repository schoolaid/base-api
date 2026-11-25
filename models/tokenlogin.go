package models

import (
	"crypto/subtle"
	"errors"
	"strings"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/core/logs"
	"github.com/go-sql-driver/mysql"
)

// MatchTokenLogin decides a POST /token login (Notion 999, PR 5's transition).
//
// ⚠️ THE PLAIN TEXT STILL DECIDES, compared by MySQL exactly as before (utf8mb3_general_ci:
// case, trailing spaces and accents are ignored), as in external-api: support changes a password
// by editing that column, and a hash of the old one must not keep it working. password_hash
// decides only in the contract step, when the plain-text column goes. Until then two log lines
// tell us when that is safe (counts per credential, never a value):
//   - "collation-only match": MySQL accepted a password an exact compare would refuse;
//   - "no password hash": a login succeeded for a credential without a password_hash.
//
// ⚠️ A BLANKED PLAIN TEXT LOGS NOTHING IN (empty, or only spaces, which PAD SPACE compares equal
// to the empty password): blanking the column disables a credential.
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
	if len(rows) != 1 || strings.TrimRight(rows[0].Password, " ") == "" {
		return 0, "", false, nil
	}
	row := rows[0]
	if subtle.ConstantTimeCompare([]byte(row.Password), []byte(password)) != 1 {
		logs.Warn("token route: collation-only match: external_user=%d", row.Id)
	}
	if hashed, known := hasPasswordHash(o, row.Id); known && !hashed {
		logs.Info("token route: no password hash: external_user=%d", row.Id)
	}
	return row.Id, row.Token, true, nil
}

// hasPasswordHash reports whether the credential has a password_hash. known is false when it
// can't tell: a database without schoolaid-admin's password_hash migration (1054), or a failed read.
func hasPasswordHash(o orm.Ormer, id int64) (hashed, known bool) {
	var n int
	err := o.Raw("SELECT COUNT(*) FROM external_user WHERE id = ? AND password_hash IS NOT NULL AND password_hash <> ''", id).QueryRow(&n)
	if err != nil {
		var me *mysql.MySQLError
		if !errors.As(err, &me) || me.Number != 1054 {
			logs.Warn("token route: password hash not read: external_user=%d: %v", id, err)
		}
		return false, false
	}
	return n == 1, true
}
