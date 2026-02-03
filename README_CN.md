# secure-kit

[![Go Reference](https://pkg.go.dev/badge/github.com/soulteary/secure-kit.svg)](https://pkg.go.dev/github.com/soulteary/secure-kit)
[![Go Report Card](https://goreportcard.com/badge/github.com/soulteary/secure-kit)](https://goreportcard.com/report/github.com/soulteary/secure-kit)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![codecov](https://codecov.io/gh/soulteary/secure-kit/graph/badge.svg)](https://codecov.io/gh/soulteary/secure-kit)

[English](README.md)

统一的 Go 服务加密工具包。提供哈希函数（Argon2、bcrypt、SHA、MD5）、安全随机数生成、常量时间比较和敏感数据脱敏工具。

## 特性

- **多种哈希算法**：Argon2id、bcrypt、SHA-256、SHA-512、MD5，统一接口
- **安全随机**：加密安全的随机字节、字符串、数字、令牌和 UUID
- **时序攻击防护**：常量时间比较函数
- **数据脱敏**：邮箱、手机号、信用卡、IP 地址、API 密钥脱敏，适用于日志记录
- **零外部依赖**：仅使用 Go 标准库和 golang.org/x/crypto

## 安装

```bash
go get github.com/soulteary/secure-kit
```

## 使用

### 哈希接口

所有哈希器实现统一的 `Hasher` 接口：

```go
type Hasher interface {
    Hash(plaintext string) (string, error)
    Verify(hash, plaintext string) bool
    Algorithm() string
}
```

### Argon2（推荐用于密码）

```go
import secure "github.com/soulteary/secure-kit"

// 使用默认参数创建
hasher := secure.NewArgon2Hasher()

// 或使用自定义参数
hasher := secure.NewArgon2Hasher(
    secure.WithArgon2Time(2),
    secure.WithArgon2Memory(64*1024),
    secure.WithArgon2Threads(4),
)

// 哈希密码
hash, err := hasher.Hash("myPassword123!")
if err != nil {
    log.Fatal(err)
}

// 验证密码
if hasher.Verify(hash, "myPassword123!") {
    fmt.Println("密码匹配！")
}

// PHC 格式（兼容其他实现）
hash, err := hasher.HashWithParams("password")
// 输出: $argon2id$v=19$m=65536,t=1,p=4$salt$hash
```

### bcrypt

```go
hasher := secure.NewBcryptHasher()

// 或使用自定义代价因子
hasher := secure.NewBcryptHasher(secure.WithBcryptCost(12))

hash, _ := hasher.Hash("password")
valid := hasher.Verify(hash, "password")
```

### SHA-256/SHA-512

```go
sha256Hasher := secure.NewSHA256Hasher()
sha512Hasher := secure.NewSHA512Hasher()

hash, _ := sha256Hasher.Hash("data")
valid := sha256Hasher.Verify(hash, "data")

// 辅助函数
sha512Hash := secure.GetSHA512Hash("text")
sha256Hash := secure.GetSHA256Hash("text")
```

### MD5（仅用于遗留系统）

```go
// 警告：MD5 已被密码学破解。仅用于遗留系统兼容。
hasher := secure.NewMD5Hasher()
hash, _ := hasher.Hash("data")

// 辅助函数
md5Hash := secure.GetMD5Hash("text")
```

### 安全随机数

```go
// 随机字节
bytes, err := secure.RandomBytes(32)

// 随机十六进制字符串
hex, err := secure.RandomHex(16) // 返回 32 字符的十六进制字符串

// 随机 Base64 字符串
b64, err := secure.RandomBase64(32)
urlSafeB64, err := secure.RandomBase64URL(32)

// 随机数字（用于 OTP 验证码）
code, err := secure.RandomDigits(6) // 例如 "847293"

// 随机字母数字字符串
token, err := secure.RandomAlphanumeric(20)

// 随机令牌（URL 安全的 base64）
token, err := secure.RandomToken(32)

// 随机 UUID（v4）
uuid, err := secure.RandomUUID() // 例如 "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"

// 随机整数
n, err := secure.RandomInt(100)           // [0, 100)
n, err := secure.RandomIntRange(10, 20)   // [10, 20]

// 自定义字符集
s, err := secure.RandomString(10, secure.CharsetAlphanumeric)
```

### 常量时间比较

```go
// 比较敏感值时防止时序攻击
if secure.ConstantTimeEqual(userInput, secretKey) {
    // 有效密钥
}

// 别名以便熟悉
secure.SecureCompare(a, b)
secure.TimingSafeEqual(a, b)
secure.ConstantTimeEqualBytes([]byte(a), []byte(b))
```

### 数据脱敏

```go
// 邮箱脱敏
secure.MaskEmail("user@example.com")        // "u***@example.com"
secure.MaskEmailPartial("john@example.com") // "jo***@example.com"

// 手机号脱敏
secure.MaskPhone("13812345678")       // "138****5678"
secure.MaskPhoneSimple("+1234567890") // "+12***7890"

// 信用卡脱敏
secure.MaskCreditCard("4111111111111111")    // "************1111"
secure.MaskCreditCard("4111-1111-1111-1111") // "****-****-****-1111"

// IP 地址脱敏
secure.MaskIPAddress("192.168.1.100") // "192.*.*.*"
secure.MaskIPAddress("2001:db8::1")   // "2001:****:****:..."

// API 密钥脱敏
secure.MaskAPIKey("sk_live_abcdefghijklmnop") // "sk_l***mnop"

// 姓名脱敏
secure.MaskName("张三") // "张***"

// 通用字符串脱敏
secure.MaskString("1234567890", 3) // "123***890"

// 截断
secure.TruncateString("很长的文本内容", 4) // "很长的文..."
```

### 兼容旧代码的解析器（Stargate 兼容性）

为了向后兼容现有代码：

```go
// 这些实现了 HashResolver 接口
var resolver secure.HashResolver

resolver = &secure.BcryptResolver{}
resolver = &secure.SHA512Resolver{}
resolver = &secure.MD5Resolver{}
resolver = &secure.PlaintextResolver{}

// 使用
if resolver.Check(storedHash, userPassword) {
    // 有效密码
}
```

## 项目结构

```
secure-kit/
├── interface.go      # Hasher 和 HashResolver 接口
├── argon2.go         # Argon2id 实现
├── bcrypt.go         # bcrypt 实现
├── sha.go            # SHA-256/SHA-512 实现
├── md5.go            # MD5 实现（遗留）
├── plaintext.go      # 明文比较（仅测试用）
├── compare.go        # 常量时间比较
├── random.go         # 安全随机数生成
├── mask.go           # 敏感数据脱敏
└── *_test.go         # 完整测试
```

## 安全建议

| 使用场景 | 推荐算法 |
|----------|---------|
| 密码哈希 | Argon2id 或 bcrypt |
| OTP/验证码 | Argon2id |
| API 令牌 | RandomToken + 常量时间比较 |
| 校验和 | SHA-256 或 SHA-512 |
| 遗留系统 | MD5（建议迁移到 Argon2） |

**切勿使用** SHA-256、SHA-512 或 MD5 进行密码哈希。这些是为完整性检查设计的快速哈希，不适用于密码安全。

本包中所有哈希校验均使用恒定时间比较，以避免时序侧信道泄露。

### 安全说明

- 长期存储建议使用 `HashWithParams`（PHC 格式），以保留 Argon2 参数。
- 若系统可能接收不可信的哈希输入，请自行限制长度/代价（例如 Argon2 参数上限、bcrypt 代价上限），避免 CPU 或内存 DoS。
- `PlaintextHasher` 与 `MD5Hasher` 仅用于遗留兼容，生产路径请避免使用。

## 集成示例

### Herald（OTP 服务）

```go
import secure "github.com/soulteary/secure-kit"

// 生成 OTP 验证码
code, _ := secure.RandomDigits(6)

// 哈希存储
hasher := secure.NewArgon2Hasher()
hash, _ := hasher.Hash(code)

// 将哈希存储到 Redis，通过短信/邮件发送验证码

// 之后验证用户输入
if hasher.Verify(storedHash, userInputCode) {
    // 有效 OTP
}
```

### Stargate（认证网关）

```go
import secure "github.com/soulteary/secure-kit"

// 使用多种算法验证密码
resolvers := map[string]secure.HashResolver{
    "bcrypt":    &secure.BcryptResolver{},
    "sha512":    &secure.SHA512Resolver{},
    "md5":       &secure.MD5Resolver{},
    "plaintext": &secure.PlaintextResolver{},
}

func verifyPassword(algorithm, hash, password string) bool {
    resolver, ok := resolvers[algorithm]
    if !ok {
        return false
    }
    return resolver.Check(hash, password)
}
```

## 要求

- Go 1.25 或更高版本
- golang.org/x/crypto（用于 Argon2 和 bcrypt）

## 测试覆盖率

运行测试：

```bash
go test ./... -v

# 带覆盖率
go test ./... -coverprofile=coverage.out -covermode=atomic
go tool cover -html=coverage.out -o coverage.html
go tool cover -func=coverage.out
```

## 基准测试

```bash
go test -bench=. -benchmem
```

## 贡献

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 提交 Pull Request

## 许可证

详见 [LICENSE](LICENSE) 文件。
