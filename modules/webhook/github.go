package webhook

import (
	"bytes"
	"io"
	"net/http"

	"github.com/Mininglamp-OSS/octo-lib/pkg/wkhttp"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func (w *Webhook) github(c *wkhttp.Context) {
	w.Debug("github webhook", zap.Any("params", c.Params))

	// 验证 GitHub HMAC-SHA256 签名
	if !w.verifyGitHubSignature(c) {
		return
	}

	result, _ := io.ReadAll(c.Request.Body)
	w.Debug("github webhook result", zap.ByteString("result", result))
}

// verifyGitHubSignature 验证 GitHub webhook 的 HMAC-SHA256 签名
// GitHub 使用 X-Hub-Signature-256 头发送签名
func (w *Webhook) verifyGitHubSignature(c *wkhttp.Context) bool {
	if w.secretKey == "" {
		w.Warn("TS_WEBHOOK_SECRET_KEY 未配置，拒绝 GitHub webhook 请求。请设置环境变量以启用安全认证。")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "服务器未配置 webhook 签名密钥"})
		return false
	}

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		w.Error("读取请求体失败", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "读取请求体失败"})
		return false
	}
	// 重置 body 供后续 handler 读取
	c.Request.Body = io.NopCloser(bytes.NewReader(body))

	signature := c.GetHeader("X-Hub-Signature-256")
	if signature == "" {
		w.Warn("GitHub Webhook请求缺少X-Hub-Signature-256签名头")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "缺少签名头X-Hub-Signature-256"})
		return false
	}

	if !VerifyHMACSHA256(body, signature, w.secretKey) {
		w.Warn("GitHub Webhook签名验证失败")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "签名验证失败"})
		return false
	}
	return true
}
