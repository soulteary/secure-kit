# secure-kit

[![Go Reference](https://pkg.go.dev/badge/github.com/soulteary/secure-kit/v2.svg)](https://pkg.go.dev/github.com/soulteary/secure-kit/v2)
[![Go Report Card](.github/goreportcard.svg)](.github/goreportcard-report.md)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![codecov](https://codecov.io/gh/soulteary/secure-kit/graph/badge.svg)](https://codecov.io/gh/soulteary/secure-kit)

[English](README.md) | [更新日志](CHANGELOG.md)

统一的 Go 服务加密工具包。提供哈希函数（Argon2、bcrypt、SHA、MD5）、安全随机数生成、
常量时间比较、HMAC 校验和敏感数据脱敏工具。根包不依赖标准库之外的任何东西——两个需要
`golang.org/x/crypto` 的密码哈希器住在 `passwd` 子包里。

> **v2.0.0 的破坏性变更——模块路径变了，密码哈希器也移进了子包。**
>
> **第一步——所有人，包括根本不做密码哈希的服务。** 模块路径现在是
> `github.com/soulteary/secure-kit/v2`：
>
> ```bash
> go get github.com/soulteary/secure-kit/v2
> go mod edit -droprequire github.com/soulteary/secure-kit
> ```
>
> 然后改掉源码里的 import 路径。主版本号必须跳，这是 Go 的导入兼容性规则决定的：
> v2 删掉了导出符号。留转发用的空壳不是一个选项——空壳自己就要 import x/crypto，
> 下面那点好处会原样吐回去。
>
> **第二步——只有用到密码哈希的人需要。** Argon2id 和 bcrypt 移到了
> `github.com/soulteary/secure-kit/v2/passwd`，于是只用 `RandomHex`、
> `ConstantTimeEqual` 或 HMAC helper 的程序导入根包时不再链接
> `golang.org/x/crypto`。对一个只导入根包的程序来说，这意味着
> **少链接 6 个包、二进制小 2.8%**（113 → 107 个包，1,884,320 → 1,831,072 字节），
> **`go.mod` 里一条 `// indirect` 都不剩**——`golang.org/x/crypto` 和
> `golang.org/x/sys` 一起消失——`go.sum` 少 4 行。
>
> 体积只是小头。真正的意义是：一个从不哈希密码的服务，不再分发、也不再需要为一个
> 它压根不调用的密码学库负责。
>
> | 改之前 | 改之后 |
> |---|---|
> | `secure.NewArgon2Hasher(...)` | `passwd.NewArgon2Hasher(...)` |
> | `secure.NewArgon2HasherStrict(...)` | `passwd.NewArgon2HasherStrict(...)` |
> | `secure.NewBcryptHasher(...)` | `passwd.NewBcryptHasher(...)` |
> | `secure.NewBcryptHasherStrict(...)` | `passwd.NewBcryptHasherStrict(...)` |
> | `secure.WithArgon2*`、`secure.WithBcryptCost` | `passwd.WithArgon2*`、`passwd.WithBcryptCost` |
> | `secure.Argon2Hasher`、`secure.BcryptHasher`、`secure.BcryptResolver` | `passwd.` 下同名 |
>
> 两者依然实现根包里的 `secure.Hasher` 和 `secure.HashResolver`，所以
> `map[string]secure.HashResolver` 加一行 import 就能继续用。盐依然取自
> `secure.RandReader()`，`secure.SetRandReader` 照旧管得住它。除此之外没有任何变化：
> 其余符号、参数默认值、哈希格式都与 v1.6.0 一致——v1 写出的哈希在 v2 下照样验得过。

## 特性

- **多种哈希算法**：Argon2id、bcrypt、SHA-256、SHA-512、MD5，统一接口
- **安全随机**：加密安全的随机字节、字符串、数字、令牌和 UUID
- **时序攻击防护**：常量时间比较函数
- **数据脱敏**：邮箱、手机号、信用卡、IP 地址、API 密钥脱敏，适用于日志记录
- **零外部依赖**：根包只用 Go 标准库——连 `golang.org/x/crypto` 都不用，那是 `passwd`
  子包才需要的
- **用多少付多少**：做密码哈希的二进制才会链接密码哈希库，不做就不链接

## 安装

```bash
go get github.com/soulteary/secure-kit/v2
```

根包不依赖标准库之外的任何东西。Argon2id 与 bcrypt 需要 `golang.org/x/crypto`，
所以它们住在自己的子包里，只有导入这个子包的程序才会链接那个依赖：

```bash
# Argon2id 与 bcrypt 密码哈希器——会链接 golang.org/x/crypto
go get github.com/soulteary/secure-kit/v2/passwd
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
import "github.com/soulteary/secure-kit/v2/passwd"

// 默认参数
hasher := passwd.NewArgon2Hasher()

// 自定义参数
hasher = passwd.NewArgon2Hasher(
    passwd.WithArgon2Time(2),
    passwd.WithArgon2Memory(64*1024),
    passwd.WithArgon2Threads(4),
)

hash, err := hasher.Hash("myPassword123!")
if err != nil {
    log.Fatal(err)
}

if hasher.Verify(hash, "myPassword123!") {
    fmt.Println("密码匹配！")
}

// PHC 格式 —— 参数与哈希一起记录
hash, err = hasher.HashWithParams("password")
// $argon2id$v=19$m=65536,t=1,p=4$salt$hash
```

#### 选项校验

超出范围的选项值会被**拒绝，而不是忽略**。`passwd.NewArgon2Hasher` 会 panic；
`passwd.NewArgon2HasherStrict` 以错误返回：

```go
import "github.com/soulteary/secure-kit/v2/passwd"

hasher, err := passwd.NewArgon2HasherStrict(passwd.WithArgon2Time(32))
if err != nil {
    // "WithArgon2Time: 32 out of range (1..16)"
}
```

| 选项 | 有效范围 |
|------|----------|
| `passwd.WithArgon2Time` | 1–16 |
| `passwd.WithArgon2Memory` | 1–524288（KiB，即最多 512 MiB） |
| `passwd.WithArgon2Threads` | 1–255 |
| `passwd.WithArgon2KeyLen` | 1–1024 |
| `passwd.WithArgon2SaltLen` | 1–1024 |

参数来自配置文件时请使用 `Strict` 构造函数，这样坏值会让启动失败，而不是让进程 panic。

#### 存储格式要有意识地选

`Hash` 产出的是简单的 `salt:hash` 格式，它**不记录任何参数**。因此 `Verify` 会用
hasher *当前*的配置重新推导：之后任何对 memory、time、threads 或 keyLen 的改动都会让
**所有已存储的哈希失效**，表现为密码错误，而且无法迁移。

`HashWithParams` 产出 PHC 格式，参数随哈希一起保存，因此提高工作因子之后旧哈希仍能
校验通过。除非已有存储强制使用简单格式，否则请用它。

### bcrypt

```go
import "github.com/soulteary/secure-kit/v2/passwd"

hasher := passwd.NewBcryptHasher()

// 或使用自定义代价因子
hasher = passwd.NewBcryptHasher(passwd.WithBcryptCost(12))

hash, _ := hasher.Hash("password")
valid := hasher.Verify(hash, "password")
```

超出范围的 cost 同样会被拒绝——`passwd.NewBcryptHasher` panic，`passwd.NewBcryptHasherStrict`
返回错误：

```go
import "github.com/soulteary/secure-kit/v2/passwd"

hasher, err := passwd.NewBcryptHasherStrict(passwd.WithBcryptCost(14))
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

### HMAC 签名

```go
verifier := secure.NewHMACVerifier(secure.HMACSHA256, "shared-secret")
verifier = secure.NewHMACVerifierFromBytes(secure.HMACSHA256, secretBytes)

sig := verifier.Sign(payload)            // 十六进制
sigB64 := verifier.SignBase64(payload)   // base64
sigPrefixed := verifier.SignWithPrefix(payload) // "sha256=<hex>"

ok := verifier.Verify(payload, sig)
ok = verifier.VerifyBase64(payload, sigB64)
```

算法：`secure.HMACSHA1`、`secure.HMACSHA256`、`secure.HMACSHA512`。一次性调用的辅助
函数是 `ComputeHMACSHA1`、`ComputeHMACSHA256` 和 `ComputeHMACSHA512`。

#### 对多个候选签名做校验

密钥轮换期间，webhook 的 header 里可能带着多个签名：

```go
candidates := secure.ExtractSignatures(r.Header.Get("X-Hub-Signature-256"), "sha256")

ok, matched := verifier.VerifyAny(payload, candidates)
if !ok {
    // 这里 matched 是空的，可以安全地打日志。
    return errUnauthorized
}
log.Printf("verified with %s", matched)
```

`matched` 是匹配上的那个签名，**没有任何匹配时它是空的**——不要指望在失败路径上拿回
期望值。`ExtractSignatures` 会统一应用前缀过滤，不管来源是单个值还是逗号分隔的列表，
并且仍然支持那些发送不带前缀签名的服务商。

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

// 自定义字符集 —— 按 rune 取值，因此非 ASCII 字符集也能用
s, err := secure.RandomString(10, secure.CharsetAlphanumeric)
s, err = secure.RandomString(10, "我你他abc")
```

字符集常量：`CharsetAlpha`、`CharsetAlphanumeric`、`CharsetAlphanumericLower`、
`CharsetAlphanumericUpper`、`CharsetDigits`、`CharsetHex`、`CharsetURLSafe`。

`RandomIntRange` 用 `big.Int` 计算区间宽度，因此整个 `int64` 范围都可用——包括
`[0, math.MaxInt64]` 和 `[math.MinInt64, math.MaxInt64]`。

`RandomBytes` 会拒绝超过 `secure.MaxRandomBytes`（1 MiB）的请求。
`RandomBytesOrPanic` 在出错时 panic 而不是返回错误。`MustRandomBytes` 行为相同，
但**已废弃**——它为兼容旧代码而保留，新代码请用 `RandomBytesOrPanic`。
`SetRandReader` 可替换熵源，仅用于测试。

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
// IPv6 固定返回第一组加七组掩码：
secure.MaskIPAddress("2001:db8::1")   // "2001:****:****:****:****:****:****:****"

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
import (
    secure "github.com/soulteary/secure-kit/v2"
    "github.com/soulteary/secure-kit/v2/passwd"
)

// 这些实现了 HashResolver 接口
var resolver secure.HashResolver

resolver = &passwd.BcryptResolver{}
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
├── sha.go            # SHA-256/SHA-512 实现
├── md5.go            # MD5 实现（遗留）
├── plaintext.go      # 明文比较（仅测试用）
├── compare.go        # 常量时间比较
├── random.go         # 安全随机数生成
├── mask.go           # 敏感数据脱敏
├── hmac.go           # HMAC 计算与校验
├── deps_test.go      # 守住「根包只用标准库」这条线
├── passwd/           # 唯一需要 golang.org/x/crypto 的包
│   ├── argon2.go     # Argon2id 实现
│   ├── bcrypt.go     # bcrypt 实现
│   └── *_test.go     # 密码哈希器的测试
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
import (
	secure "github.com/soulteary/secure-kit/v2"
	"github.com/soulteary/secure-kit/v2/passwd"
)

// 生成 OTP 验证码
code, _ := secure.RandomDigits(6)

// 哈希存储
hasher := passwd.NewArgon2Hasher()
hash, _ := hasher.Hash(code)

// 将哈希存储到 Redis，通过短信/邮件发送验证码

// 之后验证用户输入
if hasher.Verify(storedHash, userInputCode) {
    // 有效 OTP
}
```

### Stargate（认证网关）

```go
import (
	secure "github.com/soulteary/secure-kit/v2"
	"github.com/soulteary/secure-kit/v2/passwd"
)

// 使用多种算法验证密码
resolvers := map[string]secure.HashResolver{
    "bcrypt":    &passwd.BcryptResolver{},
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

## 升级说明（v2.0.0）

完整的版本历史见 [CHANGELOG.md](CHANGELOG.md)。

**模块路径变了，密码哈希器也移了位置。** 两步都写在文件开头的提示框里，简而言之：

```diff
-import secure "github.com/soulteary/secure-kit"
+import (
+    secure "github.com/soulteary/secure-kit/v2"
+    "github.com/soulteary/secure-kit/v2/passwd"
+)

-hasher := secure.NewArgon2Hasher()
+hasher := passwd.NewArgon2Hasher()
```

从不哈希密码的服务只需要这个 diff 的第一行，代价换来的是 `go.mod` 里少掉
`golang.org/x/crypto` 与 `golang.org/x/sys`。

哈希格式、参数默认值、行为都没有变——v1.6.0 写出的哈希在 v2.0.0 下照样验得过。
`secure.Hasher`、`secure.HashResolver`、`secure.SetRandReader` 以及其余东西都留在根包。

## 升级说明（v1.6.0）

**有两个构造函数现在会 panic，而它们此前只是默默给了你一个比你要求的更弱的 hasher。**
这是修复，不是回归。

- **超出范围的选项值会被拒绝，而不是丢弃。** `WithArgon2Time(32)` 此前让工作因子停在
  `1`，`WithBcryptCost(14)` 让 cost 停在 `10`——不报错、不 panic、也无从察觉。调用方相信
  存下来的哈希比实际更强，而对一个存在意义就是"强度"的参数来说，这是最糟糕的失效方式。
  现在 `passwd.NewArgon2Hasher` 和 `passwd.NewBcryptHasher` 遇到非法值会 **panic**；
  `passwd.NewArgon2HasherStrict` 和 `passwd.NewBcryptHasherStrict` 以错误返回。**如果你的选项值来自
  配置，请改用 `Strict` 构造函数**，这样坏值会让启动失败而不是让进程挂掉——并且请检查
  你传过的值里有没有本来就超范围的，因为那些已存储的哈希比你预期的更弱。
- **`VerifyAny` 在失败时不再返回期望签名。** 第二个返回值的文档是"匹配上的签名"，而在
  失败路径上它是刚被拒绝的那个 payload 的正确 HMAC——于是任何打日志或回显它的调用方都
  **发布了一个可伪造的值**。现在除非真有匹配，它就是空的。
- **`RandomString` 按 rune 取值，而不是按字节。** 这个参数的文档说的是字符集；按字节取值
  会切断多字节 rune，对任何非 ASCII 字符集都产出非法 UTF-8。
- **`RandomIntRange` 支持完整的 `int64` 范围。** `max-min+1` 此前在 `int64` 里计算，
  于是 `[0, MaxInt64]` 得到负的上界并报错，`[MinInt64, MaxInt64]` 则回绕。现在区间宽度
  用 `big.Int` 计算。
- **`ExtractSignatures` 统一做前缀过滤。** 单值路径此前完全跳过了过滤，于是
  `"sha1=xyz"` 会作为候选的 `sha256` 签名返回，而同一个值出现在逗号分隔列表里时却会被
  正确丢弃。
- **只是补充文档、行为未变**：简单的 `salt:hash` Argon2 格式不记录参数，因此 `Verify`
  会用 hasher *当前*的设置重新推导，任何参数改动都会让所有已存储的哈希以"密码错误"
  失效。除非已有存储强制使用简单格式，否则请用 `HashWithParams`（PHC）。
- **要求里写的是 Go 1.26**；`go.mod` 需要 `1.27.0`。

## 要求

- **Go 1.27+**（`go.mod` 声明 `go 1.27.0`）
- golang.org/x/crypto —— 只有 `passwd` 子包（Argon2 与 bcrypt）需要；根包只用标准库

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
