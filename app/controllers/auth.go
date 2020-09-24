package controllers

import (
	"encoding/base64"
	"fmt"
	"github.com/RangelReale/htpasswd-auth/app/models"
	"github.com/revel/revel"
	"net/http"
	"strings"
	"time"
)

type Auth struct {
	*revel.Controller
}

func (c Auth) Index() revel.Result {
	return c.Redirect(Auth.Login)
}

func (c Auth) Login(redirectUrl string) revel.Result {
	c.ViewArgs["redirectUrl"] = redirectUrl
	return c.Render()
}

func ValidationErrorMessage(v *revel.Validation) string {
	elist := []string{}
	for _, e := range v.Errors {
		elist = append(elist, e.String())
	}
	return strings.Join(elist, "<br/>")
}

func (c Auth) LoginSave(username, password, redirectUrl string) revel.Result {
	user := &models.User{
		Username: username,
		Password: password,
	}
	user.Validate(c.Validation)

	if c.Validation.HasErrors() {
		// Store the validation errors in the flash context and redirect.
		c.Validation.Keep()
		c.FlashParams()
		//c.Flash.Error("Login failed")
		c.Flash.Error(ValidationErrorMessage(c.Validation))
		return c.Redirect(Auth.Login)
	}

	// Encode cookie like Base Auth
	cookieValue := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", user.Username, user.Password)))

	// Set cookie expiration (by default, 24 hours)
	expiration := time.Now().Add(time.Duration(revel.Config.IntDefault("htpa.cookieExpireMinutes", int(24 * time.Hour))))

	c.SetCookie(&http.Cookie{
		Name: revel.Config.StringDefault("htpa.cookieName", "htpa_auth"),
		Value: cookieValue,
		Path: "/",
		Domain: revel.Config.StringDefault("htpa.cookieDomain", ""),
		Expires: expiration,
	})

	if strings.TrimSpace(redirectUrl) == "" {
		return c.Redirect(Auth.LoginOk)
	}
	return c.Redirect(redirectUrl)
}

func (c Auth) LoginOk() revel.Result {
	return c.Render()
}

func (c Auth) Logout() revel.Result {
	return c.Render()
}

