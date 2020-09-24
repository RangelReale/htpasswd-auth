package models

import (
	"fmt"
	"github.com/RangelReale/htpasswd-auth/app"
	"github.com/revel/revel"
)

type User struct {
	Username, Password string
}

func (u *User) String() string {
	return fmt.Sprintf("User(%s)", u.Username)
}

func (user *User) Validate(v *revel.Validation) {
	v.Check(user.Username,
		revel.Required{},
		revel.MaxSize{100},
		revel.MinSize{4},
	)

	v.Check(user.Password,
		revel.Required{},
		revel.MaxSize{60},
		revel.MinSize{4},
	)

	if !v.HasErrors() {
		if !app.HtPasswd.Match(user.Username, user.Password) {
			v.Error("Invalid user/password combination")
		}
	}
}
