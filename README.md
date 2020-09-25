# A nginx `auth_request` and traefik `ForwardAuth` authentication service, based on cookies and htpasswd.

Authentication service for
nginx's
[`ngx_http_auth_request_module`](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) 
or traefik's [`ForwardAuth middleware`](https://doc.traefik.io/traefik/middlewares/forwardauth/),
verifying that session cookies are valid and allowing users to log in
using a
[`htpasswd`](https://httpd.apache.org/docs/current/programs/htpasswd.html) file.

This program uses [Revel](https://revel.github.io/), a Golang web framework.

## Installation

`revel run .`

## Configuration

The configurations are in the file conf/app.conf.

Some parameters can be passed as environment variables, which is useful on Docker.

```
# Auth url (default blank)
HTPA_AUTHURL
# Username header (default blank)
HTPA_USERNAMEHEADER
# htpassword file name [REQUIRED] (default blank)
HTPA_HTPASSWDFILE
# Cookie name (default: htpa_auth)
HTPA_COOKIENAME
# Cookie domain (default blank)
HTPA_COOKIEDOMAIN
# Cookie expire minutes (default: 24 hours)
HTPA_COOKIEEXPIREMINUTES
# Cookie check cache time in minutes (default: 10 minutes - <= 0 to disable)
HTPA_COOKIECHECKCACHEMINUTES

```

### Author

[Rangel Reale](https://github.com/RangelReale)
