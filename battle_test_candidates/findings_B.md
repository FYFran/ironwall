# findings_B — Codex 盲审报告

**目标**: mayank-ramnani/secure-file-management (544行Python)
**方法论**: OWASP Top 10 2021 + 密码学误用 + 路径安全 + 授权完整性 + 日志泄露
**审计者**: Codex (DeepSeek-v4-pro) — 盲审, 不知道findings_A
**日期**: 2026-07-10

---

## 🔴 CRITICAL (4)

### C1. debug=True → Werkzeug RCE
- **文件**: run.py:36
- **CWE**: CWE-489
- **要点**: debug模式暴露/console端点 → 任意Python执行

### C2. 全站无CSRF保护
- **文件**: app/routes.py — 所有POST路由
- **CWE**: CWE-352
- **要点**: register/login/upload/share/delete/unshare全无CSRF token

### C3. /upload和/share缺少@login_required
- **文件**: app/routes.py:144, 240
- **CWE**: CWE-306
- **要点**: 未认证用户可访问关键功能入口。当前因nullable=False隐性防护，非有效安全边界

### C4. 日志明文记录PII
- **文件**: app/routes.py:90-91, 116, 145, 148
- **CWE**: CWE-532
- **要点**: 记录email、user ID、sha256 hash、token片段

---

## 🟠 HIGH (5)

### H1. Session Fixation — 登录后不重新生成session
- **文件**: app/routes.py — login_user()后
- **CWE**: CWE-384

### H2. 无文件上传大小限制 → 磁盘DoS
- **文件**: app/routes.py — /upload
- **CWE**: CWE-770

### H3. 无登录频率限制 → 暴力枚举+锁定oracle
- **文件**: app/routes.py:93 — /login
- **CWE**: CWE-307

### H4. 硬编码Let's Encrypt证书路径泄露IP
- **文件**: run.py:28-29
- **CWE**: CWE-200

### H5. 登录锁返回不同错误消息 → 用户存在性泄露
- **文件**: app/routes.py:103-106 vs 127-129
- **CWE**: CWE-204

---

## 🟡 MEDIUM (6)

### M1. DownloadToken竞态条件(TOCTOU)
- **文件**: app/routes.py:222-226
- **CWE**: CWE-367

### M2. 注册端点枚举已有用户
- **文件**: app/routes.py:67-71
- **CWE**: CWE-204

### M3. SQLite数据库文件明文落盘
- **文件**: app/__init__.py:27
- **CWE**: CWE-312

### M4. Session Cookie缺少安全属性
- **文件**: app/__init__.py
- **CWE**: CWE-614

### M5. 日志保留策略过小 → 取证丢失
- **文件**: app/__init__.py:39-42
- **CWE**: CWE-778

### M6. Token消费在文件传输之前 → 失败无法重试
- **文件**: app/routes.py:225-226
- **CWE**: CWE-754

---

## 🟢 LOW (4)

### L1. 文件扩展名可被双层扩展名绕过
- **文件**: app/routes.py:33
- **CWE**: CWE-434

### L2. 密码强度正则过于排他
- **文件**: app/routes.py:37-48
- **CWE**: CWE-521

### L3. 锁定后无限重试 → 绕过锁
- **文件**: app/routes.py:107
- **CWE**: CWE-645

### L4. Fernet密钥无轮换机制
- **文件**: app/__init__.py:22-24
- **CWE**: CWE-321

---

**总计**: 19 findings | 4 CRITICAL / 5 HIGH / 6 MEDIUM / 4 LOW
*审计完成: 2026-07-10 | 审计者: Codex (DeepSeek-v4-pro)*
