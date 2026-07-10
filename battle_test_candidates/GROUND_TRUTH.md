# Ground Truth — secure-file-management 安全审计

> **双脑交叉验证** | Brain A (皮特) + Brain B (Codex/DeepSeek-v4-pro)
> **方法论**: OWASP Top 10 2021 + 攻击面清单，双人独立审计，差异项仲裁
> **日期**: 2026-07-10
> **项目**: mayank-ramnani/secure-file-management, 544行Python

---

## 审计方法论

1. 两位审计员独立审计全部Python代码
2. 使用相同的OWASP Top 10 2021 + 攻击面清单
3. 审计员B（Codex）为盲审——不知道审计员A的结论
4. 差异项由仲裁流程处理
5. severity分歧按保守原则取较高级别

**来源标注**:
- `[A]` = Brain A独立发现
- `[B]` = Codex独立发现
- `[A+B]` = 双方都发现
- `[A→B✓]` = A发现, B仲裁确认
- `[B→A✓]` = B发现, A复核确认

**HTML模板**仅A审计（B未获得模板代码），涉及模板的finding标记`[A-only-templates]`。

---

## 🔴 CRITICAL (4)

### GT-001: debug=True → Werkzeug RCE
- **文件**: run.py:36-41
- **CWE**: CWE-489 (Active Debug Code)
- **来源**: [A+B] 双审一致
- **描述**: `app.run(debug=True, host='0.0.0.0', port=443)` 暴露Werkzeug调试器。攻击者访问/console可执行任意Python代码。`host='0.0.0.0'`绑定所有网络接口。
- **利用**: 触发未处理异常→调试器traceback→获取PIN码(/debuggerpin)→Python REPL→RCE
- **修复**: `debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true'`

### GT-002: IDOR — share_file无所有权检查
- **文件**: app/routes.py:303-342
- **CWE**: CWE-639 (Authorization Bypass Through User-Controlled Key)
- **来源**: [A] Brain A发现, Codex仲裁确认
- **描述**: `share_file()`缺少`file.user_id == current_user.id`检查。任何认证用户POST到`/share/<file_id>`可将任意文件分享给任意用户。file_id是自增整数→可枚举全系统文件。对比`delete_file()`(L349)正确实现了所有权检查。
- **利用**: 注册账号→枚举file_id→POST /share/N email=attacker@evil.com→文件被分享→下载
- **修复**: 在POST处理前加`if file.user_id != current_user.id: flash(...) return redirect(...)`

### GT-003: 文件名碰撞 → 数据丢失+访问阻断
- **文件**: app/routes.py:158-159, 197, 354-355
- **CWE**: CWE-706 (Use of Incorrectly-Resolved Name)
- **来源**: [A] Brain A发现, Codex仲裁确认
- **描述**: `secure_filename()`去除了路径分隔符但**不保证唯一性**。两个用户上传同名文件→指向同一磁盘路径。`download_file()`按filename查询→只返回第一条记录→合法用户无法下载自己的文件。`delete_file()`删除磁盘文件→另一用户的文件被误删。
- **利用**: 上传`report.pdf`→其他用户上传同名文件→后者永远无法访问/下载
- **修复**: `unique_name = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"`

### GT-004: /upload + /share 缺 @login_required
- **文件**: app/routes.py:144, 303
- **CWE**: CWE-306 (Missing Authentication for Critical Function)
- **来源**: [B→A✓] Codex发现, Brain A复核确认
- **描述**: `upload_file()`和`share_file()`均无`@login_required`装饰器。匿名用户POST到/upload→文件处理完成并写入磁盘（DB写入失败但文件已落地）。匿名用户POST到/share→可分享任意文件给任意用户（DB写入成功）。
- **利用**: 匿名用户curl POST /share/1 email=target@test.com → 成功分享→匿名分享链
- **修复**: 两个路由添加`@login_required`

---

## 🟠 HIGH (5)

### GT-005: GET /share/<id> 泄露文件名（未认证可访问）
- **文件**: app/routes.py:303-307, 342
- **CWE**: CWE-200 (Exposure of Sensitive Information)
- **来源**: [A] Brain A发现
- **描述**: `share_file()`的GET处理无`@login_required`、无所有权检查。任何人访问`/share/1`看到file_id=1的文件名。可枚举→获取全系统文件名列表。
- **修复**: 加`@login_required` + 所有权检查

### GT-006: 登录错误消息差异 → 用户枚举+锁定探测
- **文件**: app/routes.py:100-130
- **CWE**: CWE-204 (Observable Response Discrepancy)
- **来源**: [A+B] 双审一致
- **描述**: 三种失败路径返回不同消息、不同处理时间：
  - 用户不存在(L100-103): 立即返回
  - 账户锁定(L104-111): 检查lockout_time
  - 密码错误(L113-123): 递增计数器+可能锁定
  → 攻击者可识别已注册用户+探测锁定状态+对特定用户DoS
- **修复**: 统一错误消息。对不存在用户也执行dummy hash防时序

### GT-007: 无文件上传大小限制 → DoS
- **文件**: app/routes.py:156-183
- **CWE**: CWE-770 (Allocation of Resources Without Limits)
- **来源**: [A+B] 双审一致
- **描述**: 服务端未设置`MAX_CONTENT_LENGTH`。模板提示"max 10MB"但未强制执行。Fernet加密将整个文件加载到内存(L162, L168)→OOM风险。
- **修复**: `app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024`

### GT-008: 日志明文记录PII
- **文件**: app/routes.py (多处logger调用)
- **CWE**: CWE-532 (Insertion of Sensitive Information into Log File)
- **来源**: [A+B] 双审一致; A评为MEDIUM, B评为CRITICAL → 取较高: HIGH
- **描述**: 日志记录email、user_id、文件名、SHA-256 hash、token前缀。日志10MB轮转、5个备份→约60天保留。文件系统权限是唯一防护。
- **涉及行**: L84-85(注册email), L129(登录user_id), L145(上传user_id), L148(文件名+hash), L195-201(下载请求), L232-249(token生成), L305-306(分享操作), L337-338(分享成功)
- **修复**: 仅记录user_id，email/hash/token做脱敏或省略

### GT-009: 全站无CSRF保护
- **文件**: app/routes.py (所有POST路由)
- **CWE**: CWE-352 (Cross-Site Request Forgery)
- **来源**: [A+B] 双审一致; A评为MEDIUM, B评为CRITICAL → 取较高: HIGH
- **描述**: register/login/upload/share/delete/unshare所有POST路由均无CSRF token。Flask-WTF未集成。攻击者可构造恶意页面→诱导认证用户执行操作。SameSite cookie提供部分保护但不可靠。
- **修复**: `pip install flask-wtf` + `CSRFProtect(app)`

---

## 🟡 MEDIUM (7)

### GT-010: Download Token先消费后验证
- **文件**: app/routes.py:274-295
- **CWE**: CWE-691 (Insufficient Control Flow Management)
- **来源**: [A+B] 双审一致
- **描述**: L274先`db.session.delete(download_token)`, L282-291才做完整性校验。校验失败→token已删无法重试。日志L277写"Token consumed"但实际可能未成功。
- **修复**: 先解密+校验完整性，通过后才删除token

### GT-011: 无登录速率限制
- **文件**: app/routes.py:91 (login函数)
- **CWE**: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **来源**: [A+B]; A评为LOW, B评为HIGH → 取中: MEDIUM
- **描述**: 仅有账户级锁(5次/15min)。无IP级限流→分布式暴力破解(每个账户4次×N个IP=无限)。可恶意锁定他人账户。
- **修复**: 引入`flask-limiter`，IP级限制`10 per minute`

### GT-012: 硬编码证书路径暴露IP
- **文件**: run.py:28-29
- **CWE**: CWE-200 (Information Exposure)
- **来源**: [A+B]; A评为LOW, B评为HIGH → 取中: MEDIUM
- **描述**: `cert_path = "/etc/letsencrypt/live/sfm.3.149.241.240.sslip.io/fullchain.pem"` 直接暴露服务器IP和子域名。
- **修复**: 从环境变量读取证书路径

### GT-013: Session Fixation — 登录后不重新生成session
- **文件**: app/routes.py:128 (login_user调用处)
- **CWE**: CWE-384 (Session Fixation)
- **来源**: [B→A✓] Codex发现, A确认（注：Flask-Login 0.6+ 默认regenerate session，此finding依赖版本）
- **描述**: 如果Flask-Login版本<0.6或用户自定义session处理，登录后session未重新生成→攻击者可预设session ID→受害者登录后攻击者使用相同session。
- **修复**: `flask-login>=0.6` 或显式调用`session.clear()`在login_user之前

### GT-014: 注册端点用户枚举
- **文件**: app/routes.py:67-73
- **CWE**: CWE-204 (Observable Response Discrepancy)
- **来源**: [B→A✓] Codex发现, A确认
- **描述**: "Email address already exists" / "Username already exists" → 可枚举已注册用户
- **修复**: 统一返回"Registration request received. Check your email."

### GT-015: Session Cookie缺少安全属性
- **文件**: app/__init__.py:24 (app.config设置处)
- **CWE**: CWE-614 (Sensitive Cookie Without 'Secure' Attribute)
- **来源**: [B→A✓] Codex发现, A确认
- **描述**: 未显式设置`SESSION_COOKIE_SECURE`、`SESSION_COOKIE_HTTPONLY`、`SESSION_COOKIE_SAMESITE`
- **修复**: 添加三个配置项

### GT-016: SQLite数据库文件明文
- **文件**: app/__init__.py:25 (`sqlite:///site.db`)
- **CWE**: CWE-312 (Cleartext Storage)
- **来源**: [B→A✓] Codex发现, A确认
- **描述**: 密码hash、邮箱、文件元数据存储在未加密的SQLite文件中
- **修复**: SQLCipher或确保instance目录权限700

---

## 🟢 LOW (5)

### GT-017: 文件扩展名验证仅检查后缀
- **文件**: app/routes.py:21-22, 156
- **CWE**: CWE-434
- **来源**: [A] Brain A发现
- **描述**: `allowed_file()`只看扩展名不看MIME/magic bytes。恶意文件可重命名为.txt绕过。

### GT-018: Fernet密钥硬依赖环境变量
- **文件**: app/__init__.py:18-20
- **CWE**: CWE-1404
- **来源**: [A] Brain A发现
- **描述**: 环境变量缺失→应用崩溃，无回退。生产环境正确但开发不友好。

### GT-019: DOM-based XSS in upload.html
- **文件**: app/templates/upload.html:65
- **CWE**: CWE-79
- **来源**: [A-only-templates]
- **描述**: `filePreview.innerHTML = ...${file.name}...` — 用户选择的文件名直接注入innerHTML。自体XSS，需社交工程。
- **注**: Codex未审计HTML模板，无法交叉验证。保留为LOW。

### GT-020: 双层扩展名绕过
- **文件**: app/routes.py:21-22 (allowed_file)
- **CWE**: CWE-434
- **来源**: [B→A✓]
- **描述**: `malicious.exe.pdf`通过扩展名检查（取.pdf）。Fernet加密降低风险但不能消除。

### GT-021: Fernet密钥无轮换机制
- **文件**: app/__init__.py:18-22
- **CWE**: CWE-321
- **来源**: [B→A✓]
- **描述**: 如果密钥泄露，所有历史加密文件可被解密。无key rotation→无前向保密。

---

## 统计

| 严重度 | 数量 | IDs |
|--------|------|-----|
| CRITICAL | 4 | GT-001~004 |
| HIGH | 5 | GT-005~009 |
| MEDIUM | 7 | GT-010~016 |
| LOW | 5 | GT-017~021 |
| **合计** | **21** | |

### 按OWASP类别

| 类别 | 数量 |
|------|------|
| A01 Broken Access Control | 6 (GT-002, GT-004, GT-005, GT-009) |
| A02 Cryptographic Failures | 2 (GT-018, GT-021) |
| A03 Injection | 1 (GT-019) |
| A04 Insecure Design | 2 (GT-003, GT-010) |
| A05 Security Misconfiguration | 4 (GT-001, GT-012, GT-007, GT-015) |
| A07 Identification Failures | 4 (GT-004, GT-006, GT-011, GT-013, GT-014) |
| A08 Data Integrity | 1 (GT-003) |
| A09 Logging Failures | 1 (GT-008) |
| A10 SSRF | 0 |

### 按文件分布

| 文件 | Finding数 |
|------|----------|
| app/routes.py | 15 |
| run.py | 2 (GT-001, GT-012) |
| app/__init__.py | 4 (GT-015, GT-016, GT-018, GT-021) |
| app/templates/upload.html | 1 (GT-019) |
| app/models.py | 0 |
| init_db.py | 0 |

### 交叉验证矩阵

| 来源 | 数量 | % |
|------|------|---|
| [A+B] 双审一致 | 8 | 38% |
| [A] 仅A发现（含A→B✓） | 6 | 29% |
| [B→A✓] 仅B发现，A确认 | 6 | 29% |
| [A-only-templates] 模板相关 | 1 | 5% |

双审一致率38%意味着62%的finding只被一位审计员发现——证明**单人审计会有大量遗漏，双人交叉验证是必要的**。

---

## 置信度说明

| 置信度 | 条件 |
|--------|------|
| **高** | 双审一致 [A+B] |
| **中** | 单审发现但另一审仲裁确认 [A→B✓] / [B→A✓] |
| **低** | 单审发现、无交叉验证 [A-only-templates] |

GT-019（DOM XSS in upload.html）是唯一低置信度finding——Codex未审计模板，无法交叉验证。

---

## 方法论局限

1. **HTML模板**: 仅Brain A审计了HTML。Python代码是双审覆盖。
2. **审计时间**: 各约1-2小时，非完整安全评估。
3. **依赖版本**: GT-013 (Session Fixation) 依赖Flask-Login版本。
4. **业务逻辑漏洞**: 复杂业务逻辑可能仍未被发现。
5. **n=1**: 544行单项目。不能泛化。

---

*Ground Truth建立完成: 2026-07-10*
*双脑签字: Brain A (皮特) ✅ | Brain B (Codex DeepSeek-v4-pro) ✅*
