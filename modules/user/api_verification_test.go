package user

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-lib/testutil"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

// 本文件主要测纯函数层（签名校验、URL 构造、JWT 格式）；
// issueVerifyToken 的 claims 断言走 testutil.NewTestServer 的轻量集成测试
// （需要 MySQL，与 api_destroy_test.go 对齐）。

func TestVerifyOCTOSignature_Valid(t *testing.T) {
	secret := "test-secret"
	body := []byte(`{"octo_user_id":"u1","real_name":"张三"}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	assert.True(t, verifyOCTOSignature(sig, body, secret))
}

func TestVerifyOCTOSignature_Mismatch(t *testing.T) {
	secret := "test-secret"
	body := []byte(`{"a":1}`)
	// 用错误密钥生成签名
	mac := hmac.New(sha256.New, []byte("wrong-secret"))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	assert.False(t, verifyOCTOSignature(sig, body, secret))
}

func TestVerifyOCTOSignature_BadPrefix(t *testing.T) {
	assert.False(t, verifyOCTOSignature("deadbeef", []byte("x"), "s"))
	assert.False(t, verifyOCTOSignature("md5=abc", []byte("x"), "s"))
	assert.False(t, verifyOCTOSignature("", []byte("x"), "s"))
}

func TestVerifyOCTOSignature_BadHex(t *testing.T) {
	assert.False(t, verifyOCTOSignature("sha256=zzzz", []byte("x"), "s"))
}

func TestBuildVerifyURL_Default(t *testing.T) {
	t.Setenv("OCTO_VERIFY_URL_BASE", "")
	t.Setenv("OCTO_VERIFY_RETURN_TO_DEFAULT", "")
	u := buildVerifyURL("tok", "")
	assert.True(t, strings.HasPrefix(u, "https://accounts.example.com/verify?token=tok"))
	assert.NotContains(t, u, "return_to=")
}

func TestBuildVerifyURL_WithReturnTo(t *testing.T) {
	t.Setenv("OCTO_VERIFY_URL_BASE", "")
	t.Setenv("OCTO_VERIFY_RETURN_TO_DEFAULT", "")
	u := buildVerifyURL("tok", "https://api.example.com/home")
	assert.Contains(t, u, "token=tok")
	// return_to 必须 QueryEscape —— 冒号 / 斜杠被 %-encoded。
	assert.Contains(t, u, "return_to="+url.QueryEscape("https://api.example.com/home"))
}

func TestBuildVerifyURL_CustomBaseWithQuery(t *testing.T) {
	t.Setenv("OCTO_VERIFY_URL_BASE", "https://verify.internal/go?env=prod")
	u := buildVerifyURL("tok", "")
	// base 已带 ?，应使用 & 分隔
	assert.Equal(t, "https://verify.internal/go?env=prod&token=tok", u)
}

// TestBuildVerifyURL_RejectsBadSchemes 确保 javascript:/data:/file: 等非法 scheme
// 被直接忽略 —— verify_url 里不应出现 return_to=。
func TestBuildVerifyURL_RejectsBadSchemes(t *testing.T) {
	t.Setenv("OCTO_VERIFY_URL_BASE", "")
	t.Setenv("OCTO_VERIFY_RETURN_TO_DEFAULT", "")
	for _, bad := range []string{
		"javascript:alert(1)",
		"JavaScript:alert(1)", // 大小写绕过
		"data:text/html,<script>alert(1)</script>",
		"file:///etc/passwd",
		"http://evil.example.com/",  // http 不在 allowlist（只允许 https）
		"ftp://example.com/x",
		"//evil.example.com/",       // 协议相对
		"  javascript:alert(1)",     // 前导空格
		"random-string-no-scheme",
	} {
		u := buildVerifyURL("tok", bad)
		assert.NotContains(t, u, "return_to=", "return_to 必须被丢弃: %q", bad)
	}
}

// TestBuildVerifyURL_AllowedSchemes 覆盖 https / octo / dmwork 三种合法 scheme。
func TestBuildVerifyURL_AllowedSchemes(t *testing.T) {
	t.Setenv("OCTO_VERIFY_URL_BASE", "")
	t.Setenv("OCTO_VERIFY_RETURN_TO_DEFAULT", "")
	for _, good := range []string{
		"https://api.example.com/home",
		"octo://profile",
		"dmwork://verify-done",
	} {
		u := buildVerifyURL("tok", good)
		assert.Contains(t, u, "return_to="+url.QueryEscape(good), "return_to 应当被保留: %q", good)
	}
}

// TestIsAllowedReturnToScheme 单测 scheme 判定逻辑。
func TestIsAllowedReturnToScheme(t *testing.T) {
	assert.True(t, isAllowedReturnToScheme("https://example.com"))
	assert.True(t, isAllowedReturnToScheme("HTTPS://EXAMPLE.COM"))
	assert.True(t, isAllowedReturnToScheme("octo://x"))
	assert.True(t, isAllowedReturnToScheme("dmwork://y"))
	assert.False(t, isAllowedReturnToScheme("http://example.com"))
	assert.False(t, isAllowedReturnToScheme("javascript:alert(1)"))
	assert.False(t, isAllowedReturnToScheme("data:text/html,x"))
	assert.False(t, isAllowedReturnToScheme(""))
}

func TestNullableString(t *testing.T) {
	n := nullableString("")
	assert.False(t, n.Valid)
	n = nullableString("   ")
	assert.False(t, n.Valid)
	n = nullableString("hello")
	assert.True(t, n.Valid)
	assert.Equal(t, "hello", n.String)
}

// TestVerifyJWT_Roundtrip 跑一次签→验闭环，保证我们签发的 token 满足 verify-service
// 侧的预期：HS256 / purpose=verify / sub=uid / exp 在 5 分钟内。
func TestVerifyJWT_Roundtrip(t *testing.T) {
	secret := []byte("jwt-secret-for-test")
	now := time.Now()
	claims := octoVerifyJWTClaims{
		Purpose: octoVerifyJWTPurpose,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(octoVerifyJWTTTL)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(secret)
	assert.NoError(t, err)
	assert.NotEmpty(t, signed)

	var parsed octoVerifyJWTClaims
	_, err = jwt.ParseWithClaims(signed, &parsed, func(tok *jwt.Token) (interface{}, error) {
		assert.Equal(t, "HS256", tok.Method.Alg())
		return secret, nil
	})
	assert.NoError(t, err)
	assert.Equal(t, "user-123", parsed.Subject)
	assert.Equal(t, "verify", parsed.Purpose)
	// TTL 正好 5 分钟
	exp := parsed.ExpiresAt.Time.Sub(parsed.IssuedAt.Time)
	assert.Equal(t, 5*time.Minute, exp)
}

// parseVerifyTokenClaims 解码 /v1/internal/verify-token 响应里的 JWT，
// 忽略签名校验（本测试只关心 claims 字段值；签名 roundtrip 另有 TestVerifyJWT_Roundtrip 覆盖）。
func parseVerifyTokenClaims(t *testing.T, body []byte) octoVerifyJWTClaims {
	t.Helper()
	var resp verifyTokenResp
	assert.NoError(t, json.Unmarshal(body, &resp))
	assert.NotEmpty(t, resp.Token, "token 必须非空: %s", string(body))

	parser := jwt.NewParser()
	var claims octoVerifyJWTClaims
	// ParseUnverified 跳过签名校验，只解码 payload。
	_, _, err := parser.ParseUnverified(resp.Token, &claims)
	assert.NoError(t, err)
	return claims
}

// TestVerifyTokenClaimsHasDisplayName 校验：
//   - 用户有 Name / ShortNo 时，签出的 JWT claims 里 display_name / short_no 都被填上，
//   - purpose / sub 与既定契约一致。
//
// 注意：claim key 叫 `short_no` 而不是 `username`，因为 Model.Username（这里
// 插入的是 `"zhangsan"`）另指登录用户名，和短号是不同的业务概念
// （codex review GH#1306 要求区分）。
func TestVerifyTokenClaimsHasDisplayName(t *testing.T) {
	t.Setenv("OCTO_JWT_SECRET", "test-jwt-secret")
	t.Setenv("OCTO_VERIFY_URL_BASE", "")
	t.Setenv("OCTO_VERIFY_RETURN_TO_DEFAULT", "")

	s, ctx := testutil.NewTestServer()
	u := New(ctx)
	assert.NoError(t, u.db.Insert(&Model{
		UID:      testutil.UID,
		Username: "zhangsan",
		Name:     "张三",
		ShortNo:  "9001",
		Status:   1,
	}))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/internal/verify-token", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("token", testutil.Token)
	req.Header.Set("Content-Type", "application/json")
	s.GetRoute().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	claims := parseVerifyTokenClaims(t, w.Body.Bytes())
	assert.Equal(t, octoVerifyJWTPurpose, claims.Purpose)
	assert.Equal(t, testutil.UID, claims.Subject)
	assert.Equal(t, "张三", claims.DisplayName)
	assert.Equal(t, "9001", claims.ShortNo)
}

// TestVerifyTokenClaimsEmptyWhenLoginInfoEmpty 校验：
//   - 用户 Name / ShortNo 均为空时，签发不 panic、不 500，
//   - JWT claims 里 DisplayName / ShortNo 都是空串（omitempty 保证 JSON 里不出现这两个 key，
//     老版 verify-service 也能正常解码），
//   - 不 fallback 到 UID（UID 不会泄露到 display_name / short_no 字段）。
func TestVerifyTokenClaimsEmptyWhenLoginInfoEmpty(t *testing.T) {
	t.Setenv("OCTO_JWT_SECRET", "test-jwt-secret")
	t.Setenv("OCTO_VERIFY_URL_BASE", "")
	t.Setenv("OCTO_VERIFY_RETURN_TO_DEFAULT", "")

	s, ctx := testutil.NewTestServer()
	u := New(ctx)
	// Name / ShortNo 故意留空，模拟老账号 / 迁移中用户。
	assert.NoError(t, u.db.Insert(&Model{
		UID:      testutil.UID,
		Username: "legacy_user",
		Status:   1,
	}))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/internal/verify-token", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("token", testutil.Token)
	req.Header.Set("Content-Type", "application/json")
	s.GetRoute().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// 解析签出的 token —— 不应 panic，claims 字段为空。
	var resp verifyTokenResp
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	claims := parseVerifyTokenClaims(t, w.Body.Bytes())
	assert.Equal(t, octoVerifyJWTPurpose, claims.Purpose)
	assert.Equal(t, testutil.UID, claims.Subject)
	assert.Equal(t, "", claims.DisplayName, "display_name 空值不应 fallback 到 UID")
	assert.Equal(t, "", claims.ShortNo, "short_no 空值不应 fallback 到 UID")
	assert.NotEqual(t, testutil.UID, claims.DisplayName)
	assert.NotEqual(t, testutil.UID, claims.ShortNo)

	// 进一步确认：omitempty 生效 → JSON payload 里没有这两个 key，老 verify-service 能忽略多余字段。
	parts := strings.Split(resp.Token, ".")
	assert.Len(t, parts, 3)
	payload, err := jwt.DecodeSegment(parts[1])
	assert.NoError(t, err)
	assert.NotContains(t, string(payload), `"display_name"`)
	assert.NotContains(t, string(payload), `"short_no"`)
}
