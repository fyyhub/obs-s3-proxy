package middleware

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
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

		// 解析Authorization: OBS AccessKey:Signature
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "OBS" {
			http.Error(w, "Invalid Authorization header format", http.StatusForbidden)
			return
		}

		keySig := strings.SplitN(parts[1], ":", 2)
		if len(keySig) != 2 {
			http.Error(w, "Invalid Authorization header format", http.StatusForbidden)
			return
		}

		accessKey := keySig[0]
		signature := keySig[1]

		// 验证access_key
		secretKey, ok := a.clients[accessKey]
		if !ok {
			http.Error(w, "Invalid AccessKey", http.StatusForbidden)
			return
		}

		// 验证时间戳 (Date header)
		dateStr := r.Header.Get("Date")
		if dateStr == "" {
			dateStr = r.Header.Get("x-obs-date")
		}
		if dateStr == "" {
			http.Error(w, "Missing Date header", http.StatusForbidden)
			return
		}

		// 验证日期是否在15分钟内
		var requestTime time.Time
		var err error
		
		// 尝试解析RFC 1123格式
		requestTime, err = time.Parse(http.TimeFormat, dateStr)
		if err != nil {
			// 尝试ISO 8601格式
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

		// 计算期望签名
		expectedSig := a.calculateSignature(r, secretKey)

		// 比较签名
		if signature != expectedSig {
			http.Error(w, "Signature mismatch", http.StatusForbidden)
			return
		}

		// 认证通过
		next.ServeHTTP(w, r)
	})
}

// calculateSignature 计算请求签名
func (a *Auth) calculateSignature(r *http.Request, secretKey string) string {
	// 构造StringToSign
	stringToSign := a.buildStringToSign(r)
	
	// 计算HMAC-SHA1
	h := hmac.New(sha1.New, []byte(secretKey))
	h.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// buildStringToSign 构造签名字符串
func (a *Auth) buildStringToSign(r *http.Request) string {
	var sb strings.Builder

	// HTTP-Verb
	sb.WriteString(r.Method)
	sb.WriteString("\n")

	// Content-MD5
	if md5 := r.Header.Get("Content-MD5"); md5 != "" {
		sb.WriteString(md5)
	}
	sb.WriteString("\n")

	// Content-Type
	if ct := r.Header.Get("Content-Type"); ct != "" {
		sb.WriteString(ct)
	}
	sb.WriteString("\n")

	// Date (如果存在x-obs-date则置空)
	date := r.Header.Get("Date")
	if r.Header.Get("x-obs-date") != "" {
		date = ""
	}
	sb.WriteString(date)
	sb.WriteString("\n")

	// CanonicalizedHeaders (x-obs-* headers)
	canonicalHeaders := a.buildCanonicalizedHeaders(r)
	for k, v := range canonicalHeaders {
		sb.WriteString(k)
		sb.WriteString(":")
		sb.WriteString(v)
		sb.WriteString("\n")
	}

	// CanonicalizedResource
	sb.WriteString(a.buildCanonicalizedResource(r))

	return sb.String()
}

// buildCanonicalizedHeaders 构造规范化headers
func (a *Auth) buildCanonicalizedHeaders(r *http.Request) map[string]string {
	result := make(map[string]string)
	
	for k, v := range r.Header {
		lowerKey := strings.ToLower(k)
		if strings.HasPrefix(lowerKey, "x-obs-") {
			if len(v) > 0 {
				// 多个值用逗号连接
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

// buildCanonicalizedResource 构造规范化资源
func (a *Auth) buildCanonicalizedResource(r *http.Request) string {
	var sb strings.Builder
	
	sb.WriteString("/")
	
	// 从Host header或路径提取bucket
	host := r.Host
	if idx := strings.Index(host, "."); idx > 0 {
		bucket := host[:idx]
		sb.WriteString(bucket)
		sb.WriteString("/")
	}
	
	// 提取object路径
	path := r.URL.Path
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	if path != "" {
		sb.WriteString(urlEncode(path))
	}
	
	// 处理子资源
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

// urlEncode URL编码
func urlEncode(s string) string {
	encoded := strings.ReplaceAll(s, "+", "%20")
	encoded = strings.ReplaceAll(encoded, "*", "%2A")
	encoded = strings.ReplaceAll(encoded, "%7E", "~")
	return encoded
}
