# 华为OBS内网S3中转服务

轻量级S3兼容代理服务,在华为云内网服务器上对外暴露标准S3接口,利用内网免费流量完成华为OBS文件上传下载。

## 功能特性

- ✅ **S3兼容接口**: 支持标准AWS S3协议
- ✅ **内网流量优化**: 利用华为云ECS与OBS内网免费流量
- ✅ **轻量级设计**: Go实现,内存占用<30MB
- ✅ **流式处理**: 支持大文件上传下载,不占用额外内存
- ✅ **双层认证**: 客户端独立AK/SK,内部OBS真实凭证隔离
- ✅ **支持多种S3工具**: AWS CLI、s3cmd、rclone、Terraform等

## 架构图

```
外部客户端 (AWS SDK / s3cmd / rclone)
        │
        │  标准S3请求 (HTTP)
        ▼
┌───────────────────────┐
│   中转服务 (:8080)     │
│   (轻量Go代理)         │
│   接收S3请求           │
│   转发至OBS内网        │
└───────────────────────┘
        │
        │  内网调用 (免费流量)
        ▼
华为OBS内网Endpoint
obs.cn-north-4.myhuaweicloud.com
```

## 快速开始

### 1. 编译

```bash
go mod tidy
go build -o obs-s3-proxy main.go
```

### 2. 配置

创建 `config.yaml`:

```yaml
# 华为云OBS配置
obs:
  # OBS终端节点,根据您的桶所在区域填写
  # 华北-北京四: obs.cn-north-4.myhuaweicloud.com
  # 华东-上海一: obs.cn-east-3.myhuaweicloud.com
  # 华南-广州: obs.cn-south-1.myhuaweicloud.com
  endpoint: "obs.cn-north-4.myhuaweicloud.com"
  
  # 华为云访问密钥AK
  access_key: "YOUR_HUAWEI_AK"
  
  # 华为云访问密钥SK
  secret_key: "YOUR_HUAWEI_SK"
  
  # OBS区域
  region: "cn-north-4"

# 中转服务配置
server:
  # 监听地址
  host: "0.0.0.0"
  
  # 监听端口
  port: 8080

# 允许访问的客户端列表
clients:
  - access_key: "client_access_key_1"
    secret_key: "client_secret_key_1"
```

### 3. 运行

```bash
./obs-s3-proxy -c config.yaml
```

## 客户端使用示例

### AWS CLI

```bash
# 配置AWS CLI
aws configure set aws_access_key_id client_access_key_1
aws configure set aws_secret_access_key client_secret_key_1
aws configure set default.region cn-north-4

# 使用中转服务
aws s3 --endpoint-url http://your-server:8080 ls
aws s3 --endpoint-url http://your-server:8080 cp file.txt s3://mybucket/file.txt
aws s3 --endpoint-url http://your-server:8080 cp s3://mybucket/file.txt download.txt
```

### s3cmd

创建配置文件 `~/.s3cfg`:

```ini
[default]
host_base = your-server:8080
host_bucket = your-server:8080/%(bucket)s
access_key = client_access_key_1
secret_key = client_secret_key_1
```

使用:

```bash
s3cmd ls
s3cmd put file.txt s3://mybucket/
s3cmd get s3://mybucket/file.txt download.txt
```

### rclone

配置 `rclone.conf`:

```ini
[huaweiproxy]
type = s3
provider = Other
endpoint = http://your-server:8080
access_key_id = client_access_key_1
secret_access_key = client_secret_key_1
```

使用:

```bash
rclone ls huaweiproxy:mybucket
rclone copy file.txt huaweiproxy:mybucket/
```

### Terraform

```hcl
terraform {
  backend "s3" {
    bucket = "mybucket"
    key    = "terraform.tfstate"
    region = "cn-north-4"
    
    endpoint = "http://your-server:8080"
    
    access_key = "client_access_key_1"
    secret_key = "client_secret_key_1"
    
    skip_region_validation = true
    skip_metadata_api_check = true
    skip_credentials_validation = true
    skip_requesting_account_id = true
  }
}
```

## 支持的S3操作

- ✅ GetObject - 下载对象
- ✅ PutObject - 上传对象
- ✅ DeleteObject - 删除对象
- ✅ ListObjects - 列举对象
- ✅ ListBuckets - 列举桶
- ✅ HeadObject - 获取对象元数据
- ✅ HeadBucket - 检查桶是否存在
- ✅ CreateBucket - 创建桶
- ✅ DeleteBucket - 删除桶

## 内网配置

### 华为云ECS内网访问OBS

1. 确保ECS与OBS在同一区域
2. 配置ECS使用华为云内网DNS:
   ```
   # /etc/resolv.conf
   nameserver 100.125.1.250
   nameserver 100.125.21.250
   ```
3. 使用普通Endpoint即可,内网访问自动生效:
   - `obs.cn-north-4.myhuaweicloud.com`
   - 不区分内外网Endpoint

## 性能优化

### 内存优化

- **流式处理**: 文件上传下载直接流式转发,不缓存完整文件
- **连接复用**: HTTP连接池复用,减少建立连接开销
- **零拷贝**: 使用 `io.Copy` 实现零拷贝数据转发

### 性能参数

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  
# 建议在代码中调整以下参数
# MaxIdleConns: 100
# MaxIdleConnsPerHost: 100
# IdleConnTimeout: 90s
```

## 安全建议

1. **HTTPS**: 生产环境建议使用HTTPS
   - 使用Nginx反向代理
   - 或配置Let's Encrypt证书

2. **网络安全组**: 限制访问来源IP

3. **AK/SK管理**: 
   - 为每个客户端颁发独立的AK/SK
   - 定期轮换密钥
   - 不要将真实OBS AK/SK暴露给客户端

4. **日志审计**: 记录所有操作日志

## 故障排查

### 签名不匹配

错误: `SignatureDoesNotMatch`

解决:
1. 检查客户端AK/SK是否正确
2. 确认客户端时间与服务器时间差<15分钟
3. 检查Header签名格式: `Authorization: OBS AK:Signature`

### 无法连接OBS

错误: `dial tcp: lookup obs.cn-north-4.myhuaweicloud.com`

解决:
1. 确认ECS已配置内网DNS
2. 检查安全组规则是否放行出站流量
3. 验证OBS Endpoint是否正确

### 内存占用高

解决:
1. 检查是否有大文件上传,流式处理应该不会占用大量内存
2. 调整HTTP连接池参数
3. 检查是否有内存泄漏

## 华为云OBS区域Endpoint对照表

| 区域 | Endpoint |
|------|----------|
| 华北-北京一 | obs.cn-north-1.myhuaweicloud.com |
| 华北-北京四 | obs.cn-north-4.myhuaweicloud.com |
| 华东-上海一 | obs.cn-east-3.myhuaweicloud.com |
| 华东-上海二 | obs.cn-east-2.myhuaweicloud.com |
| 华南-广州 | obs.cn-south-1.myhuaweicloud.com |

更多区域请参考: https://developer.huaweicloud.com/endpoint

## 参考文档

- [华为OBS签名机制](https://support.huaweicloud.com/api-obs/obs_04_0010.html)
- [华为OBS Endpoint和访问域名](https://support.huaweicloud.com/productdesc-obs/obs_03_0152.html)
- [Velero使用OBS S3兼容API](https://support.huaweicloud.com/bestpractice-cce/cce_bestpractice_0310.html)
- [Terraform OBS Backend配置](https://bbs.huaweicloud.com/blogs/442623)

## License

MIT License
