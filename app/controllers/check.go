package controllers

import (
	"github.com/revel/revel"
)

type Check struct {
	*revel.Controller
}

func (c Check) Index() revel.Result {
	return c.Render()
}
