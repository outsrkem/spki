package route

import (
	"context"
	"net/http"
	"spki/src/service/cacert"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/utils"
)

func helloWord() func(ctx context.Context, c *app.RequestContext) {
	return func(ctx context.Context, c *app.RequestContext) {
		c.JSON(http.StatusOK, utils.H{"message": "hello word"})
	}
}

func Routes(r *server.Hertz) {
	r.GET("/", helloWord())
	r.POST("/spki/ca/init", apc("snms:class:createClass"), cacert.InitCa())
}
