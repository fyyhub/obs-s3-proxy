package config

import (
	"os"
	"gopkg.in/yaml.v3"
)

// Config 主配置结构
type Config struct {
	OBS     OBSConfig `yaml:"obs"`
	Server  ServerConfig `yaml:"server"`
	Clients []Client    `yaml:"clients"`
}

// OBSConfig 华为OBS配置
type OBSConfig struct {
	Endpoint  string `yaml:"endpoint"`   // obs.cn-north-4.myhuaweicloud.com
	AccessKey string `yaml:"access_key"` // 华为云AK
	SecretKey string `yaml:"secret_key"` // 华为云SK
	Region    string `yaml:"region"`     // cn-north-4
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Host string `yaml:"host"` // 监听地址，默认 0.0.0.0
	Port int    `yaml:"port"` // 监听端口，默认 8080
}

// Client 客户端凭证
type Client struct {
	AccessKey string `yaml:"access_key"` // 客户端AK
	SecretKey string `yaml:"secret_key"` // 客户端SK
}

// LoadConfig 从文件加载配置
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// 设置默认值
	if cfg.Server.Host == "" {
		cfg.Server.Host = "0.0.0.0"
	}
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}

	return &cfg, nil
}
