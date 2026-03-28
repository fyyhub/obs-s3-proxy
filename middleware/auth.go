package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"obs-s3-proxy/config"
)

// Auth 认证中间件
type Auth struct {
	clients map[string]string // access_key -> secret_key
}

// NewAuth 创建认证中间件
func NewAuth(clientList []config.Client) *Auth {
	clients := make(map[string]string)
	for _, c := range clientList {
		clients[c.AccessKey] = c.SecretKey
	}
	return &Auth{clients: clients}
}

// Middleware 认证中间件
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 如果是健康检查，直接放行
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		// 获取Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusForbidden)
			return
		}

		// 判断签名类型
		if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256") {
			// AWS S3 V4 签名
			a.handleAWSV4Auth(w, r, authHeader, next)
		} else if strings.HasPrefix(authHeader, "OBS ") {
			// OBS 签名
			a.handleOBSAuth(w, r, authHeader, next)
		} else if strings.HasPrefix(authHeader, "AWS ") {
			// AWS S3 V2 签名
			a.handleAWSV2Auth(w, r, authHeader, next)
		} else {
			http.Error(w, "Unsupported Authorization format", http.StatusForbidden)
		}
	})
}

// ==================== AWS S3 V4 签名验证 ====================

func (a *Auth) handleAWSV4Auth(w http.ResponseWriter, r *http.Request, authHeader string, next http.Handler) {
	// 解析: AWS4-HMAC-SHA256 Credential=AK/date/region/s3/aws4_request, SignedHeaders=..., Signature=...
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		http.Error(w, "Invalid AWS4 Authorization header", http.StatusForbidden)
		return
	}

	params := make(map[string]string)
	for _, part := range strings.Split(parts[1], ", ") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			params[kv[0]] = kv[1]
		}
	}

	credential := params["Credential"]
	signedHeadersStr := params["SignedHeaders"]
	clientSignature := params["Signature"]

	if credential == "" || signedHeadersStr == "" || clientSignature == "" {
		http.Error(w, "Missing required AWS4 auth parameters", http.StatusForbidden)
		return
	}

	// 解析 Credential: AK/20260328/ap-southeast-1/s3/aws4_request
	credParts := strings.SplitN(credential, "/", 5)
	if len(credParts) != 5 {
		http.Error(w, "Invalid Credential format", http.StatusForbidden)
		return
	}

	accessKey := credParts[0]
	dateStamp := credParts[1]
	region := credParts[2]
	service := credParts[3]
	// credParts[4] == "aws4_request"

	// 验证 access_key
	secretKey, ok := a.clients[accessKey]
	if !ok {
		http.Error(w, "Invalid AccessKey", http.StatusForbidden)
		return
	}

	// 验证时间 (x-amz-date 或 Date)
	amzDate := r.Header.Get("X-Amz-Date")
	if amzDate == "" {
		http.Error(w, "Missing X-Amz-Date header", http.StatusForbidden)
		return
	}

	requestTime, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		http.Error(w, "Invalid X-Amz-Date format", http.StatusForbidden)
		return
	}

	now := time.Now().UTC()
	diff := now.Sub(requestTime)
	if diff < -15*time.Minute || diff > 15*time.Minute {
		http.Error(w, "Request expired", http.StatusForbidden)
		return
	}

	// 计算期望签名
	expectedSig := a.calculateAWSV4Signature(r, secretKey, dateStamp, region, service, signedHeadersStr, amzDate)

	if clientSignature != expectedSig {
		http.Error(w, "Signature mismatch", http.StatusForbidden)
		return
	}

	// 认证通过
	next.ServeHTTP(w, r)
}

func (a *Auth) calculateAWSV4Signature(r *http.Request, secretKey, dateStamp, region, service, signedHeadersStr, amzDate string) string {
	// Step 1: 创建规范请求 (Canonical Request)
	canonicalRequest := a.buildCanonicalRequestV4(r, signedHeadersStr)

	// Step 2: 创建待签名字符串 (String to Sign)
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	hashedCanonicalRequest := sha256Hex(canonicalRequest)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", amzDate, credentialScope, hashedCanonicalRequest)

	// Step 3: 计算签名密钥 (Signing Key)
	signingKey := a.deriveSigningKey(secretKey, dateStamp, region, service)

	// Step 4: 计算签名
	signature := hmacSHA256Hex(signingKey, stringToSign)

	return signature
}

func (a *Auth) buildCanonicalRequestV4(r *http.Request, signedHeadersStr string) string {
	// HTTPMethod
	method := r.Method

	// CanonicalURI
	canonicalURI := r.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	// 对路径进行URI编码（但保留 /）
	canonicalURI = uriEncode(canonicalURI, false)

	// CanonicalQueryString
	canonicalQueryString := a.buildCanonicalQueryStringV4(r.URL.Query())

	// CanonicalHeaders & SignedHeaders
	signedHeaders := strings.Split(signedHeadersStr, ";")
	var canonicalHeadersBuilder strings.Builder
	for _, h := range signedHeaders {
		h = strings.TrimSpace(h)
		var val string
		if h == "host" {
			val = r.Host
		} else {
			val = strings.TrimSpace(r.Header.Get(h))
		}
		canonicalHeadersBuilder.WriteString(h)
		canonicalHeadersBuilder.WriteString(":")
		canonicalHeadersBuilder.WriteString(val)
		canonicalHeadersBuilder.WriteString("\n")
	}

	// HashedPayload
	hashedPayload := r.Header.Get("X-Amz-Content-Sha256")
	if hashedPayload == "" {
		hashedPayload = "UNSIGNED-PAYLOAD"
	}

	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeadersBuilder.String(),
		signedHeadersStr,
		hashedPayload,
	)
}

func (a *Auth) buildCanonicalQueryStringV4(query url.Values) string {
	if len(query) == 0 {
		return ""
	}

	var keys []string
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		values := query[k]
		sort.Strings(values)
		for _, v := range values {
			parts = append(parts, fmt.Sprintf("%s=%s", url.QueryEscape(k), url.QueryEscape(v)))
		}
	}

	return strings.Join(parts, "&")
}

func (a *Auth) deriveSigningKey(secretKey, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	return kSigning
}

// ==================== OBS 签名验证 ====================

func (a *Auth) handleOBSAuth(w http.ResponseWriter, r *http.Request, authHeader string, next http.Handler) {
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		http.Error(w, "Invalid OBS Authorization header", http.StatusForbidden)
		return
	}

	keySig := strings.SplitN(parts[1], ":", 2)
	if len(keySig) != 2 {
		http.Error(w, "Invalid OBS Authorization header format", http.StatusForbidden)
		return
	}

	accessKey := keySig[0]
	signature := keySig[1]

	secretKey, ok := a.clients[accessKey]
	if !ok {
		http.Error(w, "Invalid AccessKey", http.StatusForbidden)
		return
	}

	// 验证时间戳
	dateStr := r.Header.Get("Date")
	if dateStr == "" {
		dateStr = r.Header.Get("x-obs-date")
	}
	if dateStr == "" {
		http.Error(w, "Missing Date header", http.StatusForbidden)
		return
	}

	var requestTime time.Time
	var err error
	requestTime, err = time.Parse(http.TimeFormat, dateStr)
	if err != nil {
		requestTime, err = time.Parse("20060102T150405Z", dateStr)
		if err != nil {
			http.Error(w, "Invalid Date format", http.StatusForbidden)
			return
		}
	}

	now := time.Now().UTC()
	diff := now.Sub(requestTime)
	if diff < -15*time.Minute || diff > 15*time.Minute {
		http.Error(w, "Request expired", http.StatusForbidden)
		return
	}

	expectedSig := a.calculateOBSSignature(r, secretKey)
	if signature != expectedSig {
		http.Error(w, "Signature mismatch", http.StatusForbidden)
		return
	}

	next.ServeHTTP(w, r)
}

func (a *Auth) calculateOBSSignature(r *http.Request, secretKey string) string {
	stringToSign := a.buildStringToSignOBS(r)
	h := hmac.New(sha1.New, []byte(secretKey))
	h.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (a *Auth) buildStringToSignOBS(r *http.Request) string {
	var sb strings.Builder

	sb.WriteString(r.Method)
	sb.WriteString("\n")

	if md5 := r.Header.Get("Content-MD5"); md5 != "" {
		sb.WriteString(md5)
	}
	sb.WriteString("\n")

	if ct := r.Header.Get("Content-Type"); ct != "" {
		sb.WriteString(ct)
	}
	sb.WriteString("\n")

	date := r.Header.Get("Date")
	if r.Header.Get("x-obs-date") != "" {
		date = ""
	}
	sb.WriteString(date)
	sb.WriteString("\n")

	canonicalHeaders := a.buildCanonicalizedHeadersOBS(r)
	for k, v := range canonicalHeaders {
		sb.WriteString(k)
		sb.WriteString(":")
		sb.WriteString(v)
		sb.WriteString("\n")
	}

	sb.WriteString(a.buildCanonicalizedResourceOBS(r))

	return sb.String()
}

func (a *Auth) buildCanonicalizedHeadersOBS(r *http.Request) map[string]string {
	result := make(map[string]string)
	for k, v := range r.Header {
		lowerKey := strings.ToLower(k)
		if strings.HasPrefix(lowerKey, "x-obs-") {
			if len(v) > 0 {
				var trimmedValues []string
				for _, val := range v {
					trimmedValues = append(trimmedValues, strings.TrimSpace(val))
				}
				result[lowerKey] = strings.Join(trimmedValues, ",")
			}
		}
	}
	return result
}

func (a *Auth) buildCanonicalizedResourceOBS(r *http.Request) string {
	var sb strings.Builder
	sb.WriteString("/")

	host := r.Host
	if idx := strings.Index(host, "."); idx > 0 {
		bucket := host[:idx]
		sb.WriteString(bucket)
		sb.WriteString("/")
	}

	path := r.URL.Path
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	if path != "" {
		sb.WriteString(obsUrlEncode(path))
	}

	query := r.URL.Query()
	if len(query) > 0 {
		subResources := []string{
			"acl", "append", "attname", "backtosource", "cors", "customdomain", "delete",
			"deletebucket", "directcoldaccess", "encryption", "inventory", "length", "lifecycle", "location", "logging",
			"metadata", "mirrorBackToSource", "modify", "name", "notification", "obscompresspolicy", "orchestration",
			"partNumber", "policy", "position", "quota", "rename", "replication", "response-cache-control",
			"response-content-disposition", "response-content-encoding", "response-content-language", "response-content-type",
			"response-expires", "restore", "storageClass", "storagePolicy", "storageinfo", "tagging", "torrent", "truncate",
			"uploadId", "uploads", "versionId", "versioning", "versions", "website", "x-image-process",
			"x-image-save-bucket", "x-image-save-object", "x-obs-security-token", "object-lock", "retention",
		}

		var resourceParams []string
		for k := range query {
			for _, sr := range subResources {
				if k == sr {
					resourceParams = append(resourceParams, k)
					break
				}
			}
		}

		if len(resourceParams) > 0 {
			sb.WriteString("?")
			for i, k := range resourceParams {
				if i > 0 {
					sb.WriteString("&")
				}
				sb.WriteString(k)
				v := query.Get(k)
				if v != "" {
					sb.WriteString("=")
					sb.WriteString(v)
				}
			}
		}
	}

	return sb.String()
}

// ==================== AWS S3 V2 签名验证 ====================

func (a *Auth) handleAWSV2Auth(w http.ResponseWriter, r *http.Request, authHeader string, next http.Handler) {
	// 解析: AWS AK:Signature
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		http.Error(w, "Invalid AWS Authorization header", http.StatusForbidden)
		return
	}

	keySig := strings.SplitN(parts[1], ":", 2)
	if len(keySig) != 2 {
		http.Error(w, "Invalid AWS Authorization header format", http.StatusForbidden)
		return
	}

	accessKey := keySig[0]
	signature := keySig[1]

	secretKey, ok := a.clients[accessKey]
	if !ok {
		http.Error(w, "Invalid AccessKey", http.StatusForbidden)
		return
	}

	// 验证时间
	dateStr := r.Header.Get("Date")
	if dateStr == "" {
		dateStr = r.Header.Get("x-amz-date")
	}
	if dateStr == "" {
		http.Error(w, "Missing Date header", http.StatusForbidden)
		return
	}

	var requestTime time.Time
	var err error
	requestTime, err = time.Parse(http.TimeFormat, dateStr)
	if err != nil {
		requestTime, err = time.Parse("20060102T150405Z", dateStr)
		if err != nil {
			http.Error(w, "Invalid Date format", http.StatusForbidden)
			return
		}
	}

	now := time.Now().UTC()
	diff := now.Sub(requestTime)
	if diff < -15*time.Minute || diff > 15*time.Minute {
		http.Error(w, "Request expired", http.StatusForbidden)
		return
	}

	expectedSig := a.calculateAWSV2Signature(r, secretKey)
	if signature != expectedSig {
		http.Error(w, "Signature mismatch", http.StatusForbidden)
		return
	}

	next.ServeHTTP(w, r)
}

func (a *Auth) calculateAWSV2Signature(r *http.Request, secretKey string) string {
	stringToSign := a.buildStringToSignAWSV2(r)
	h := hmac.New(sha1.New, []byte(secretKey))
	h.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (a *Auth) buildStringToSignAWSV2(r *http.Request) string {
	var sb strings.Builder

	sb.WriteString(r.Method)
	sb.WriteString("\n")

	if md5 := r.Header.Get("Content-MD5"); md5 != "" {
		sb.WriteString(md5)
	}
	sb.WriteString("\n")

	if ct := r.Header.Get("Content-Type"); ct != "" {
		sb.WriteString(ct)
	}
	sb.WriteString("\n")

	date := r.Header.Get("Date")
	if r.Header.Get("x-amz-date") != "" {
		date = ""
	}
	sb.WriteString(date)
	sb.WriteString("\n")

	// x-amz-* headers
	var amzKeys []string
	for k := range r.Header {
		lowerKey := strings.ToLower(k)
		if strings.HasPrefix(lowerKey, "x-amz-") {
			amzKeys = append(amzKeys, lowerKey)
		}
	}
	sort.Strings(amzKeys)
	for _, k := range amzKeys {
		vals := r.Header.Values(k)
		sb.WriteString(k)
		sb.WriteString(":")
		sb.WriteString(strings.Join(vals, ","))
		sb.WriteString("\n")
	}

	// Resource
	sb.WriteString(r.URL.Path)

	return sb.String()
}

// ==================== 工具函数 ====================

func sha256Hex(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func hmacSHA256Hex(key []byte, data string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func obsUrlEncode(s string) string {
	encoded := strings.ReplaceAll(s, "+", "%20")
	encoded = strings.ReplaceAll(encoded, "*", "%2A")
	encoded = strings.ReplaceAll(encoded, "%7E", "~")
	return encoded
}

// uriEncode 对URI路径进行编码，encodeSlash控制是否编码 /
func uriEncode(s string, encodeSlash bool) string {
	var sb strings.Builder
	for _, c := range []byte(s) {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' || c == '~' || c == '.' {
			sb.WriteByte(c)
		} else if c == '/' && !encodeSlash {
			sb.WriteByte(c)
		} else {
			sb.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return sb.String()
}
