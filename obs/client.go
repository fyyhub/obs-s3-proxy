package obs

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Client OBS客户端
type Client struct {
	Endpoint   string
	AccessKey  string
	SecretKey  string
	Region     string
	HTTPClient *http.Client
}

// NewClient 创建新的OBS客户端
func NewClient(endpoint, accessKey, secretKey, region string) *Client {
	return &Client{
		Endpoint:  endpoint,
		AccessKey: accessKey,
		SecretKey: secretKey,
		Region:    region,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Minute, // 长超时支持大文件上传
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// OBS子资源列表
var subResources = []string{
	"acl", "append", "attname", "backtosource", "cors", "customdomain", "delete",
	"deletebucket", "directcoldaccess", "encryption", "inventory", "length", "lifecycle", "location", "logging",
	"metadata", "mirrorBackToSource", "modify", "name", "notification", "obscompresspolicy", "orchestration",
	"partNumber", "policy", "position", "quota", "rename", "replication", "response-cache-control",
	"response-content-disposition", "response-content-encoding", "response-content-language", "response-content-type",
	"response-expires", "restore", "storageClass", "storagePolicy", "storageinfo", "tagging", "torrent", "truncate",
	"uploadId", "uploads", "versionId", "versioning", "versions", "website", "x-image-process",
	"x-image-save-bucket", "x-image-save-object", "x-obs-security-token", "object-lock", "retention",
}

// isSubResource 检查是否为子资源
func isSubResource(key string) bool {
	for _, sr := range subResources {
		if sr == key {
			return true
		}
	}
	return false
}

// SignRequest 为请求生成OBS签名
func (c *Client) SignRequest(method string, bucket, object string, headers http.Header, query url.Values) string {
	// 构造StringToSign
	stringToSign := c.buildStringToSign(method, bucket, object, headers, query)

	log.Printf("[DEBUG] OBS StringToSign: %q", stringToSign)

	// 计算签名
	signature := c.hmacSha1(stringToSign)

	// 构造Authorization header
	return fmt.Sprintf("OBS %s:%s", c.AccessKey, signature)
}

// buildStringToSign 构造签名字符串
func (c *Client) buildStringToSign(method, bucket, object string, headers http.Header, query url.Values) string {
	var sb strings.Builder

	// HTTP-Verb
	sb.WriteString(method)
	sb.WriteString("\n")

	// Content-MD5
	if md5 := headers.Get("Content-MD5"); md5 != "" {
		sb.WriteString(md5)
	}
	sb.WriteString("\n")

	// Content-Type
	if ct := headers.Get("Content-Type"); ct != "" {
		sb.WriteString(ct)
	}
	sb.WriteString("\n")

	// Date (如果存在x-obs-date则置空)
	date := headers.Get("Date")
	if headers.Get("X-Obs-Date") != "" {
		date = ""
	}
	sb.WriteString(date)
	sb.WriteString("\n")

	// CanonicalizedHeaders (sorted)
	canonicalizedHeaders := c.buildCanonicalizedHeaders(headers)
	// canonicalizedHeaders is already sorted
	for _, kv := range canonicalizedHeaders {
		sb.WriteString(kv)
		sb.WriteString("\n")
	}

	// CanonicalizedResource
	sb.WriteString(c.buildCanonicalizedResource(bucket, object, query))

	return sb.String()
}

// buildCanonicalizedHeaders 构造规范化headers，返回排序后的 "key:value" 列表
func (c *Client) buildCanonicalizedHeaders(headers http.Header) []string {
	var result []string

	for k, v := range headers {
		lowerKey := strings.ToLower(k)
		if strings.HasPrefix(lowerKey, "x-obs-") {
			if len(v) > 0 {
				var trimmedValues []string
				for _, val := range v {
					trimmedValues = append(trimmedValues, strings.TrimSpace(val))
				}
				result = append(result, lowerKey+":"+strings.Join(trimmedValues, ","))
			}
		}
	}

	sort.Strings(result)
	return result
}

// buildCanonicalizedResource 构造规范化资源
func (c *Client) buildCanonicalizedResource(bucket, object string, query url.Values) string {
	var sb strings.Builder

	sb.WriteString("/")

	if bucket != "" {
		sb.WriteString(bucket)
		sb.WriteString("/")

		if object != "" {
			sb.WriteString(object)
		}
	}

	// 处理query参数
	if len(query) > 0 {
		var resourceParams []string
		for k := range query {
			if isSubResource(k) {
				resourceParams = append(resourceParams, k)
			}
		}

		if len(resourceParams) > 0 {
			sort.Strings(resourceParams)
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

// hmacSha1 计算HMAC-SHA1
func (c *Client) hmacSha1(data string) string {
	h := hmac.New(sha1.New, []byte(c.SecretKey))
	h.Write([]byte(data))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// ProxyRequest 代理请求到OBS
func (c *Client) ProxyRequest(r *http.Request, bucket, object string) (*http.Response, error) {
	// 构造目标URL — 使用虚拟主机风格: https://bucket.endpoint/object
	var objectPath string
	if object != "" {
		objectPath = "/" + object
	} else {
		objectPath = "/"
	}

	targetURL := fmt.Sprintf("https://%s.%s%s", bucket, c.Endpoint, objectPath)
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	log.Printf("[DEBUG] Proxy target URL: %s", targetURL)

	// 创建新请求
	var body io.Reader
	if r.Body != nil {
		body = r.Body
	}

	proxyReq, err := http.NewRequest(r.Method, targetURL, body)
	if err != nil {
		return nil, err
	}

	// 设置 Content-Length（从原始请求复制）
	proxyReq.ContentLength = r.ContentLength

	// 构造干净的 headers — 只保留 OBS 需要的
	proxyReq.Header = make(http.Header)

	// 复制 Content-Type
	if ct := r.Header.Get("Content-Type"); ct != "" {
		proxyReq.Header.Set("Content-Type", ct)
	}

	// 复制 Content-MD5
	if md5 := r.Header.Get("Content-MD5"); md5 != "" {
		proxyReq.Header.Set("Content-MD5", md5)
	}

	// 复制 Expect header (用于 100-continue)
	if expect := r.Header.Get("Expect"); expect != "" {
		proxyReq.Header.Set("Expect", expect)
	}

	// 复制 Content-Encoding
	if ce := r.Header.Get("Content-Encoding"); ce != "" {
		proxyReq.Header.Set("Content-Encoding", ce)
	}

	// 复制 Cache-Control
	if cc := r.Header.Get("Cache-Control"); cc != "" {
		proxyReq.Header.Set("Cache-Control", cc)
	}

	// 复制 Content-Disposition
	if cd := r.Header.Get("Content-Disposition"); cd != "" {
		proxyReq.Header.Set("Content-Disposition", cd)
	}

	// 设置 Host
	proxyReq.Host = fmt.Sprintf("%s.%s", bucket, c.Endpoint)

	// 先设置 Date，再计算签名（签名依赖 Date）
	dateStr := time.Now().UTC().Format(http.TimeFormat)
	proxyReq.Header.Set("Date", dateStr)

	// 注入OBS认证签名
	query := r.URL.Query()
	signature := c.SignRequest(r.Method, bucket, object, proxyReq.Header, query)
	proxyReq.Header.Set("Authorization", signature)

	log.Printf("[DEBUG] Proxy request: %s %s, Auth: %s", proxyReq.Method, targetURL, signature)

	// 发送请求
	return c.HTTPClient.Do(proxyReq)
}

// ListBuckets 列举所有桶
func (c *Client) ListBuckets() (*http.Response, error) {
	targetURL := fmt.Sprintf("https://%s", c.Endpoint)

	proxyReq, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	proxyReq.Host = c.Endpoint

	// 先设置 Date
	dateStr := time.Now().UTC().Format(http.TimeFormat)
	proxyReq.Header.Set("Date", dateStr)

	// 再计算签名
	signature := c.SignRequest("GET", "", "", proxyReq.Header, url.Values{})
	proxyReq.Header.Set("Authorization", signature)

	return c.HTTPClient.Do(proxyReq)
}

// ErrorResponse OBS错误响应
type ErrorResponse struct {
	XMLName   string `xml:"Error"`
	Code      string `xml:"Code"`
	Message   string `xml:"Message"`
	Resource  string `xml:"Resource"`
	RequestID string `xml:"RequestId"`
}

// ParseError 解析OBS错误响应
func ParseError(resp *http.Response) (*ErrorResponse, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(body, &errResp); err != nil {
		errResp.Message = string(body)
	}

	errResp.Code = fmt.Sprintf("%d", resp.StatusCode)
	return &errResp, nil
}
