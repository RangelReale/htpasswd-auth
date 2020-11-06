@echo off

rem user: test, password: test
set HTPA_HTPASSWDFILE=sample\htpasswd

revel run . -m prod
rem revel run . -m dev
