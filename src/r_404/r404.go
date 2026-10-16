package r_404

import (
	"context"
	"net/http"
	"spki/src/pkg/answer"

	"github.com/cloudwego/hertz/pkg/app"
)

func R404Handler() func(ctx context.Context, c *app.RequestContext) {
	return func(ctx context.Context, c *app.RequestContext) {
		c.JSON(http.StatusNotFound, answer.ResBody(answer.Ecode404, "The API does not exist.", nil))
	}
}
