package controllers

import (
	"encoding/base64"
	"fmt"
	"github.com/RangelReale/htpasswd-auth/app"
	"github.com/revel/revel"
	"net/http"
	"net/url"
	"strings"
)

type Check struct {
	*revel.Controller
}

func (c Check) Index() revel.Result {
	//fmt.Printf("----- HEADERS BEGIN -----\n")
	//for _, header := range c.Request.Header.Server.GetKeys() {
	//	fmt.Printf("Header: %s -- Value: %s\n", header, c.Request.Header.Server.Get(header))
	//
	//}
	//fmt.Printf("----- HEADERS END -----\n")

	cookie, err := c.Request.Cookie(revel.Config.StringDefault("htpa.cookieName", "htpa_auth"))
	if err == nil {
		if cookie != nil && cookie.GetValue() != "" {
			// c.Log.Debugf("Cookie value: %s", cookie.GetValue())
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
		aurl, err := url.Parse(authUrl)
		if err == nil {
			fwdProto := c.Request.Header.Get("X-Forwarded-Proto")
			fwdMethod := c.Request.Header.Get("X-Forwarded-Method")
			fwdHost := c.Request.Header.Get("X-Forwarded-Host")
			fwdPort := c.Request.Header.Get("X-Forwarded-Port")
			fwdUri := c.Request.Header.Get("X-Forwarded-Uri")
			fwdUpgradeInsecure := c.Request.Header.Get("Upgrade-Insecure-Requests")

			if strings.ToUpper(fwdMethod) == "GET" && fwdProto != "" && fwdHost != "" {
				q := aurl.Query()
				if q.Get("redirectUrl") == "" {
					if fwdProto == "http" && (fwdUpgradeInsecure == "1" || fwdPort == "443") {
						fwdProto = "https"
					}
					redirectUrl := fmt.Sprintf("%s://%s%s", fwdProto, fwdHost, fwdUri)
					q.Set("redirectUrl", redirectUrl)
					aurl.RawQuery = q.Encode()
					c.Log.Debug("Built redirectUrl from request: %s", redirectUrl)
					//fmt.Printf("Check RedirectUrl: %s \n", redirectUrl)
				}
			}

			return c.Redirect(aurl.String())
		} else {
			c.Log.Warnf("Error parsing auth url: %s", err.Error())
			return c.Redirect(authUrl)
		}
	}

	c.Response.Status = http.StatusForbidden
	return c.RenderText("Forbidden")
}
