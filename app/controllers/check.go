package controllers

import (
	"encoding/base64"
	"github.com/RangelReale/htpasswd-auth/app"
	"github.com/revel/revel"
	"net/http"
	"strings"
)

type Check struct {
	*revel.Controller
}

func (c Check) Index() revel.Result {
	cookie, err := c.Request.Cookie(revel.Config.StringDefault("htpa.cookieName", "htpa_auth"))
	if err == nil {
		if cookie != nil && cookie.GetValue() != "" {
			c.Log.Warnf("Cookie value: %s", cookie.GetValue())
			authstr, err := base64.StdEncoding.DecodeString(cookie.GetValue())
			if err == nil {
				authpair := strings.SplitN(string(authstr), ":", 2)
				if len(authpair) == 2 {
					if app.HtPasswd.Match(authpair[0], authpair[1]) {
						c.Response.Status = http.StatusOK
						unheader := revel.Config.StringDefault("htpa.usernameHeader", "")
						if unheader != "" {
							c.Response.Out.Header().Add(unheader, authpair[0])
						}

						return c.RenderText("OK")
					}
				} else {
					c.Log.Warn("Cookie must have exactly 2 items")
				}
			} else {
				c.Log.Warnf("Error decoding cookie: %s", err.Error())
			}
		}
	} else {
		if err != http.ErrNoCookie {
			c.Log.Warnf("Error reading cookie: %s", err.Error())
		}
	}

	authUrl := revel.Config.StringDefault("htpa.authUrl", "")
	if strings.TrimSpace(authUrl) != "" {
		return c.Redirect(authUrl)
	}
	c.Response.Status = http.StatusForbidden
	return c.RenderText("Forbidden")
}
