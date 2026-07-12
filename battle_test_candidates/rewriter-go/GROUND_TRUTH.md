# Ground Truth — rewriter-go (TokenLine Backend)

> Brain A审计 | 2026-07-12 | 6,826行 Go
> 已加固生产环境 (fail2ban+UFW+JWT+env config+Sentry/GlitchTip)

## 安全亮点
- 配置全从环境变量读取 (requireEnv + envOr) — 无硬编码密钥
- JWT认证中间件 (middleware/auth.go)
- 速率限制 (middleware/ratelimit.go)
- Sentry/GlitchTip错误追踪
- unrolled/secure安全头中间件
- 数据库迁移系统

## 🔴 CRITICAL (0)
无。

## 🟠 HIGH (0)  
无。生产环境已加固。

## 🟡 MEDIUM (1)

### GT-RW-001: Admin端点依赖Header而非JWT
- **文件**: internal/handler/admin.go
- **CWE**: CWE-306
- **代码**: Admin端点检查`X-Admin-Key` header而非JWT
- **影响**: Header可被中间人截获, 不如JWT安全
- **修复**: 改用JWT+admin role claim

## 🟢 LOW (2)

### GT-RW-002: Debug端点暴露
- **文件**: main.go (cachedCertExpiry)
- **CWE**: CWE-200
- **影响**: 证书过期信息可被探测
- **修复**: 生产环境移除debug端点

### GT-RW-003: Go pprof默认启用
- **CWE**: CWE-200  
- **影响**: pprof端点暴露运行时信息
- **修复**: 条件启用pprof (仅开发环境)

## 统计

| 严重度 | 数量 |
|--------|------|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 1 |
| LOW | 2 |
| **合计** | **3** |

---
*Brain A审计 | 2026-07-12*
