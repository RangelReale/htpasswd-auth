package app

import (
	"fmt"
	"github.com/karlseguin/ccache/v2"
	"github.com/revel/revel"
	"github.com/revel/revel/logger"
	"github.com/tg123/go-htpasswd"
	"os"
)

var (
	// AppVersion revel app version (ldflags)
	AppVersion string

	// BuildTime revel app build-time (ldflags)
	BuildTime string
)

func init() {
	// Filters is the default set of global filters.
	revel.Filters = []revel.Filter{
		revel.PanicFilter,             // Recover from panics and display an error page instead.
		revel.RouterFilter,            // Use the routing table to select the right Action
		revel.FilterConfiguringFilter, // A hook for adding or removing per-Action filters.
		revel.ParamsFilter,            // Parse parameters into Controller.Params.
		revel.SessionFilter,           // Restore and write the session cookie.
		revel.FlashFilter,             // Restore and write the flash cookie.
		revel.ValidationFilter,        // Restore kept validation errors and save new ones from cookie.
		revel.I18nFilter,              // Resolve the requested language
		HeaderFilter,                  // Add some security based headers
		revel.InterceptorFilter,       // Run interceptors around the action.
		revel.CompressFilter,          // Compress the result.
		revel.BeforeAfterFilter,       // Call the before and after filter functions
		revel.ActionInvoker,           // Invoke the action.
	}

	//revel.OnAppStart(InitializeJSONLogs)
	revel.OnAppStart(InitializeHtPasswd)
	revel.OnAppStart(InitializeCheckCache)
}

// HeaderFilter adds common security headers
// There is a full implementation of a CSRF filter in
// https://github.com/revel/modules/tree/master/csrf
var HeaderFilter = func(c *revel.Controller, fc []revel.Filter) {
	c.Response.Out.Header().Add("X-Frame-Options", "SAMEORIGIN")
	c.Response.Out.Header().Add("X-XSS-Protection", "1; mode=block")
	c.Response.Out.Header().Add("X-Content-Type-Options", "nosniff")
	c.Response.Out.Header().Add("Referrer-Policy", "strict-origin-when-cross-origin")

	fc[0](c, fc[1:]) // Execute the next filter stage.
}

var HtPasswd *htpasswd.File

func HtPasswdBadLine(err error) {
	revel.AppLog.Error(fmt.Sprintf("Bad line in password file: %s", err.Error()))
}

// NOT WORKING
func InitializeJSONLogs() {
	revel.AppLog.Info("Configuring json logs")

	logger.LogFunctionMap["stdoutjson"] =
		func(c *logger.CompositeMultiHandler, options *logger.LogOptions) {
			// Set the json formatter to os.Stdout, replace any existing handlers for the level specified
			c.SetJson(os.Stdout, options)
		}

	logger.LogFunctionMap["stderrjson"] =
		func(c *logger.CompositeMultiHandler, options *logger.LogOptions) {
			// Set the json formatter to os.Stdout, replace any existing handlers for the level specified
			c.SetJson(os.Stderr, options)
		}
}

func InitializeHtPasswd() {
	revel.AppLog.Info("Loading htpasswd file")

	htpasswdfile := revel.Config.StringDefault("htpa.htpasswdFile", "")
	if htpasswdfile == "" {
		revel.AppLog.Fatal(fmt.Sprintf("Htpasswd file was not set"))
		return
	}

	var err error
	HtPasswd, err = htpasswd.New(htpasswdfile, htpasswd.DefaultSystems, HtPasswdBadLine)
	if err != nil {
		revel.AppLog.Fatal(fmt.Sprintf("Error loading file '%s': %s", htpasswdfile, err.Error()))
		return
	}
}

var CheckCache *ccache.Cache

func InitializeCheckCache() {
	revel.AppLog.Info("Initializing check cache")
	CheckCache = ccache.New(ccache.Configure().MaxSize(100).ItemsToPrune(10))
}
