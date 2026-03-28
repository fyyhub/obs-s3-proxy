package obs

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Client OBS客户端
type Client struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	Region    string
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
	if headers.Get("x-obs-date") != "" {
		date = ""
	}
	sb.WriteString(date)
	sb.WriteString("\n")
	
	// CanonicalizedHeaders
	canonicalizedHeaders := c.buildCanonicalizedHeaders(headers)
	for k, v := range canonicalizedHeaders {
		sb.WriteString(k)
		sb.WriteString(":")
		sb.WriteString(v)
		sb.WriteString("\n")
	}
	
	// CanonicalizedResource
	sb.WriteString(c.buildCanonicalizedResource(bucket, object, query))
	
	return sb.String()
}

// buildCanonicalizedHeaders 构造规范化headers
func (c *Client) buildCanonicalizedHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)
	
	// 收集所有x-obs-开头的header
	var keys []string
	for k := range headers {
		lowerKey := strings.ToLower(k)
		if strings.HasPrefix(lowerKey, "x-obs-") {
			keys = append(keys, lowerKey)
		}
	}
	
	// 排序
	sort.Strings(keys)
	
	// 构造map
	for _, k := range keys {
		values := headers[k]
		if len(values) > 0 {
			// 多个值用逗号连接
			var trimmedValues []string
			for _, v := range values {
				trimmedValues = append(trimmedValues, strings.TrimSpace(v))
			}
			result[k] = strings.Join(trimmedValues, ",")
		}
	}
	
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
			sb.WriteString(urlEncode(object))
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

// urlEncode URL编码
func urlEncode(s string) string {
	encoded := url.QueryEscape(s)
	// OBS要求的特殊处理
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	encoded = strings.ReplaceAll(encoded, "*", "%2A")
	encoded = strings.ReplaceAll(encoded, "%7E", "~")
	encoded = strings.ReplaceAll(encoded, "%2F", "/")
	return encoded
}

// ProxyRequest 代理请求到OBS
func (c *Client) ProxyRequest(r *http.Request, bucket, object string) (*http.Response, error) {
	// 构造目标URL
	targetURL := fmt.Sprintf("https://%s.%s%s", bucket, c.Endpoint, r.URL.Path)
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}
	
	// 创建新请求
	var body io.Reader
	if r.Body != nil {
		body = r.Body
	}
	
	proxyReq, err := http.NewRequest(r.Method, targetURL, body)
	if err != nil {
		return nil, err
	}
	
	// 复制headers
	proxyReq.Header = make(http.Header)
	for k, v := range r.Header {
		// 跳过某些headers
		lowerKey := strings.ToLower(k)
		if lowerKey == "authorization" || lowerKey == "host" {
			continue
		}
		proxyReq.Header[k] = v
	}
	
	// 设置Host
	proxyReq.Host = fmt.Sprintf("%s.%s", bucket, c.Endpoint)
	
	// 注入OBS认证签名
	query := r.URL.Query()
	signature := c.SignRequest(r.Method, bucket, object, proxyReq.Header, query)
	proxyReq.Header.Set("Authorization", signature)
	proxyReq.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	
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
	
	// 注入签名
	signature := c.SignRequest("GET", "", "", proxyReq.Header, url.Values{})
	proxyReq.Header.Set("Authorization", signature)
	proxyReq.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	
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
		// 尝试XML解析
		if strings.Contains(string(body), "<Error>") {
			// 简单提取错误信息
			errResp.Message = string(body)
		} else {
			errResp.Message = string(body)
		}
	}
	
	errResp.Code = fmt.Sprintf("%d", resp.StatusCode)
	return &errResp, nil
}
