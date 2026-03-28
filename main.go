package main

import (
	"flag"
	"log"
	"net/http"
	"strconv"
	
	"obs-s3-proxy/config"
	"obs-s3-proxy/handler"
	"obs-s3-proxy/middleware"
	"obs-s3-proxy/obs"
)

func main() {
	// 解析命令行参数
	configPath := flag.String("c", "config.yaml", "配置文件路径")
	flag.Parse()
	
	// 加载配置
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("[FATAL] 加载配置失败: %v", err)
	}
	
	log.Printf("[INFO] 配置加载成功, 服务将监听 %s:%d", cfg.Server.Host, cfg.Server.Port)
	log.Printf("[INFO] OBS Endpoint: %s, Region: %s", cfg.OBS.Endpoint, cfg.OBS.Region)
	
	// 创建OBS客户端
	obsClient := obs.NewClient(
		cfg.OBS.Endpoint,
		cfg.OBS.AccessKey,
		cfg.OBS.SecretKey,
		cfg.OBS.Region,
	)
	
	// 创建代理处理器
	proxyHandler := handler.NewProxyHandler(obsClient)
	
	// 创建认证中间件
	authMiddleware := middleware.NewAuth(cfg.Clients)
	
	// 设置路由
	mux := http.NewServeMux()
	
	// 健康检查端点
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	})
	
	// 所有其他请求走代理
	mux.Handle("/", authMiddleware.Middleware(proxyHandler))
	
	// 创建HTTP服务器
	addr := cfg.Server.Host + ":" + strconv.Itoa(cfg.Server.Port)
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	
	// 启动服务器
	log.Printf("[INFO] 华为OBS内网S3中转服务启动中...")
	log.Printf("[INFO] 访问地址: http://%s", addr)
	
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("[FATAL] 服务器启动失败: %v", err)
	}
}
