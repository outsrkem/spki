package route

import (
	"context"
	"encoding/json"
	"spki/src/config"
	"spki/src/pkg/answer"
	"spki/src/pkg/common"
	"spki/src/pkg/core"
	"spki/src/slog"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/google/uuid"
	"github.com/hiuias/uias-sdk-go"
)

const xRequestIdKey = "X-Request-id"
const xAuthTokenKey = "X-Auth-Token"

func RequestId() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		klog := slog.FromContext(c)
		xRequestId := string(c.GetHeader("X-Request-Id"))
		if xRequestId == "" {
			xRequestId = strings.ReplaceAll(uuid.New().String(), "-", "")
			c.Request.Header.Set("X-Request-Id", xRequestId)
			klog.Warnf("request id is empty, Set a new request id: %s", xRequestId)
		}
		c.Set("xRequestId", xRequestId)
		c.Next(ctx)
		if c.Response.Header.Get("X-Request-Id") == "" {
			c.Response.Header.Set("X-Request-Id", xRequestId)
			klog.Debugf("Set X-Request-Id in response: %s", xRequestId)
		}
	}
}

func RequestRecorder() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		klog := slog.FromContext(c)
		start := time.Now()
		c.Next(ctx)
		stop := time.Now()
		latency := stop.Sub(start)
		klog.Infof("|%14s | %d |%7s %s",
			latency, c.Response.StatusCode(), string(c.Request.Method()), c.Request.URI().String())
	}
}

// 验证Action权限
func apc(action string) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		klog := slog.FromContext(c)
		client := uias.NewClientBuilder().
			WithEndpoint(config.AppCfg.Spki.Uias.Endpoint).
			WithTimeout(10 * time.Second).
			WithSkipTlsVerify(false).
			Build()

		type actionRaw struct {
			Uias struct {
				Action string `json:"action"`
			} `json:"uias"`
		}

		var raw actionRaw
		raw.Uias.Action = action
		rawBody, err := json.Marshal(raw)
		if err != nil {
			klog.Errorf("Error marshaling audit log: %v", err)
			c.Abort()
			return
		}

		resp, err := client.VerifyAction(ctx, c.Request.Header.Get(xRequestIdKey), c.Request.Header.Get(xAuthTokenKey), rawBody)
		if err != nil {
			klog.Warnf("Permission verification error, upstream exception: %v", err)
			c.JSON(500, resp)
			c.Abort()
			return
		}

		// 先验证权限
		if resp.Data.Payload.Authentication != 1 {
			// 没有权限，返回403和上游返回体
			klog.Warnf("Permission denial. result: %+v", resp)
			c.JSON(403, resp.Data)
			c.Abort()
			return
		}

		// 在查询实例
		klog.Infof("Domain.Id: [%s]", resp.Data.Payload.User.Domain.Id)
		instanceId, err := core.GetInstanceId(klog, resp.Data.Payload.User.Domain.Id)
		if err != nil {
			klog.Errorf("Error getting instance id: %v", err)
			c.JSON(404, answer.ResBody(answer.EcodeInstance404, "No instance found.", nil))
			c.Abort()
			return
		}

		klog.Info("Permission is granted, and the operation is authorized.")
		klog.Infof("instance id [%s]", instanceId)
		c.Set("instanceId", instanceId)
		c.Set("domainId", resp.Data.Payload.User.Domain.Id)
		c.Set("domainName", resp.Data.Payload.User.Domain.Name)
		c.Set("userId", resp.Data.Payload.User.Id)
		c.Set("account", resp.Data.Payload.User.Name.Account)
		info := &common.UserInfo{
			InstanceID: instanceId,
			DomainID:   resp.Data.Payload.User.Domain.Id,
			DomainName: resp.Data.Payload.User.Domain.Name,
			UserID:     resp.Data.Payload.User.Id,
			Account:    resp.Data.Payload.User.Name.Account,
		}
		ctx = common.WithContext(ctx, info)
		klog.Debug("end check action")
		c.Next(ctx)
	}
}
