package handler

import (
	"io"
	"log"
	"net/http"
	"strings"
	"time"
	
	"obs-s3-proxy/obs"
)

// ProxyHandler 代理处理器
type ProxyHandler struct {
	OBSClient *obs.Client
}

// NewProxyHandler 创建代理处理器
func NewProxyHandler(client *obs.Client) *ProxyHandler {
	return &ProxyHandler{OBSClient: client}
}

// ServeHTTP 处理HTTP请求
func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	
	// 解析路径，提取bucket和object
	bucket, object := p.parsePath(r)
	
	// 记录请求日志
	log.Printf("[INFO] %s %s bucket=%s object=%s", r.Method, r.URL.Path, bucket, object)
	
	// 如果没有bucket，说明是列举桶请求
	if bucket == "" {
		p.handleListBuckets(w, r)
		return
	}
	
	// 转发请求到OBS
	resp, err := p.OBSClient.ProxyRequest(r, bucket, object)
	if err != nil {
		log.Printf("[ERROR] Proxy request failed: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	// 复制响应头
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	
	// 设置响应状态码
	w.WriteHeader(resp.StatusCode)
	
	// 流式复制响应体
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("[ERROR] Failed to copy response body: %v", err)
		return
	}
	
	// 记录响应日志
	duration := time.Since(start)
	log.Printf("[INFO] %s %s -> %d (%v)", r.Method, r.URL.Path, resp.StatusCode, duration)
}

// parsePath 解析路径，提取bucket和object
func (p *ProxyHandler) parsePath(r *http.Request) (bucket, object string) {
	// 方式1: 从Host header提取bucket (虚拟主机风格)
	// 例如: bucket.obs-proxy.com -> bucket
	host := r.Host
	if idx := strings.Index(host, "."); idx > 0 {
		bucket = host[:idx]
	}
	
	// 方式2: 从URL路径提取bucket (路径风格)
	// 例如: /bucket/object -> bucket, object
	path := r.URL.Path
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	
	if bucket == "" && path != "" {
		// 路径风格
		parts := strings.SplitN(path, "/", 2)
		bucket = parts[0]
		if len(parts) > 1 {
			object = parts[1]
		}
	} else if bucket != "" {
		// 虚拟主机风格
		object = path
	}
	
	return bucket, object
}

// handleListBuckets 处理列举桶请求
func (p *ProxyHandler) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	
	resp, err := p.OBSClient.ListBuckets()
	if err != nil {
		log.Printf("[ERROR] List buckets failed: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	// 复制响应头
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	
	// 设置响应状态码
	w.WriteHeader(resp.StatusCode)
	
	// 复制响应体
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("[ERROR] Failed to copy response body: %v", err)
		return
	}
}
