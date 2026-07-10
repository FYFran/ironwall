# findings_A — Brain A 手工审计报告

**目标**: mayank-ramnani/secure-file-management (544行Python + 6 HTML模板)
**方法论**: OWASP Top 10 2021 + 攻击面清单（密码学、文件操作、认证、授权、日志）
**审计者**: 皮特 (Brain A)
**日期**: 2026-07-10

---

## 审计清单覆盖

- A01:2021 Broken Access Control
- A02:2021 Cryptographic Failures
- A03:2021 Injection
- A04:2021 Insecure Design
- A05:2021 Security Misconfiguration
- A07:2021 Identification and Authentication Failures
- A08:2021 Software and Data Integrity Failures
- A09:2021 Security Logging and Monitoring Failures
- 专门: Fernet密钥管理、token熵源、文件路径安全、授权完整性

---

## 🔴 CRITICAL

### F-001: debug=True in production — Werkzeug RCE
**文件**: run.py:37
**CWE**: CWE-489 (Active Debug Code) / CWE-94 (Code Injection)
**来源**: A05 Security Misconfiguration

`app.run(debug=True, host='0.0.0.0', port=443)` — Werkzeug debugger在debug模式下启用。攻击者如果能访问/debuggerpin或通过stack trace获取调试器PIN码，可在服务器上执行任意Python代码。`host='0.0.0.0'`使该端口对所有网络接口开放。

**利用条件**: 攻击者能触发未处理异常（例如上传无效文件、访问不存在的file_id导致404模板错误）
**影响**: 完全远程代码执行
**修复**:
```python
# run.py — 修改前
app.run(debug=True, ssl_context=ssl_context, host='0.0.0.0', port=443)
# 修改后
debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
app.run(debug=debug_mode, ssl_context=ssl_context, host='0.0.0.0', port=443)
```

### F-002: IDOR in share_file — 任意用户可分享任意文件
**文件**: app/routes.py:303-342
**CWE**: CWE-639 (Authorization Bypass Through User-Controlled Key)
**来源**: A01 Broken Access Control

`share_file()` 缺少文件所有权检查。任何认证用户POST到 `/share/<file_id>` 即可将任意文件分享给任意用户（含自身）。`file_id`是自增整数，可轻松枚举。

```python
# app/routes.py:303-308 — 当前代码
@main.route('/share/<int:file_id>', methods=['GET', 'POST'])
def share_file(file_id):
    file = File.query.get_or_404(file_id)
    if request.method == 'POST':
        email = request.form.get('email')
        # ⚠️ 没有检查 file.user_id == current_user.id
```

对比 `delete_file()` (L345-351) 正确检查了所有权。

**利用步骤**:
1. 注册账号
2. 枚举file_id: POST /share/1 email=attacker@evil.com
3. 文件被分享给攻击者
4. GET /generate-download-link/1 → 下载受害者文件

**影响**: 任何认证用户可访问所有用户上传的文件
**修复**: 在POST处理前添加：
```python
if file.user_id != current_user.id:
    flash('You do not have permission to share this file')
    return redirect(url_for('main.index'))
```

### F-003: 文件名碰撞导致数据丢失
**文件**: app/routes.py:158-159, 197, 354-355
**CWE**: CWE-706 (Use of Incorrectly-Resolved Name) / CWE-821 (Incorrect Synchronization)
**来源**: A04 Insecure Design

`secure_filename()` 去除了路径分隔符但不保证唯一性。两个用户上传同名文件（如 "report.pdf"）→ `os.path.join(UPLOAD_FOLDER, "report.pdf")` 指向同一磁盘路径。

具体影响：
- **下载歧义**: `download_file()` (L197) 按filename查File→只返回第一条记录。用户B的"report.pdf"永远无法下载
- **删除冲突**: `delete_file()` (L354) 删除磁盘文件→另一用户的文件也被删

**影响**: 合法用户无法访问自己的文件；合法用户文件被误删
**修复**: 上传时使用UUID重命名：
```python
import uuid
safe_name = secure_filename(file.filename)
unique_name = f"{uuid.uuid4().hex}_{safe_name}"
file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_name)
```

---

## 🟡 HIGH

### F-004: GET /share/<id> 泄露任意文件元数据
**文件**: app/routes.py:303-307, 342
**CWE**: CWE-200 (Exposure of Sensitive Information)
**来源**: A01 Broken Access Control

`share_file()` 的GET处理无认证要求，无所有权检查。任何人访问 `/share/1` 即可看到文件ID=1的文件名。file_id可枚举→可获取系统上所有文件的完整文件名列表。

**影响**: 文件名信息泄露（可能含敏感信息如用户名、项目名）
**修复**: 添加 `@login_required` 和所有权检查

### F-005: 认证时间侧信道 — 用户枚举 + 锁定状态泄露
**文件**: app/routes.py:91-131
**CWE**: CWE-204 (Observable Response Discrepancy) / CWE-208 (Timing Side Channel)
**来源**: A07 Identification Failures

登录流程对三种失败返回不同响应：
1. 用户不存在(L100-103): 立即返回
2. 账户已锁定(L104-111): 先检查lockout_time
3. 密码错误(L113-123): 递增计数器+可能触发锁定

每个路径执行不同的DB操作和条件分支。攻击者可通过响应时间差异判断：
- 账户是否存在（短延迟=不存在 vs 长延迟=存在+密码检查）
- 账户是否被锁定（不同的错误消息内容）

**影响**: 用户枚举、锁定状态探测、针对特定用户的定向DoS（连续5次错误密码锁定目标账户）
**修复**: 统一三条路径的响应时间和消息：
```python
# 统一错误消息，对不存在用户也执行hash检查(防时序)
user = User.query.filter_by(email=email).first()
# 始终执行密码hash操作（即使user不存在也做dummy hash）
if user:
    result = check_password_hash(user.password, password)
else:
    # dummy hash to prevent timing difference
    check_password_hash('pbkdf2:sha256:...', 'dummy')
    result = False
# 统一响应
if not result:
    flash('Invalid email or password')
```

### F-006: 文件上传无服务端大小限制
**文件**: app/routes.py:156-183
**CWE**: CWE-770 (Allocation of Resources Without Limits)
**来源**: A05 Security Misconfiguration

模板提示"max 10MB"但服务端未验证文件大小。攻击者可上传大文件耗尽磁盘空间（DoS）。另外Fernet加密将整个文件加载到内存(L162: `file.read()`, L168: `encrypt()`)，大文件会导致OOM。

**影响**: DoS（磁盘耗尽 + 内存耗尽）
**修复**:
```python
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB
```

---

## 🟠 MEDIUM

### F-007: Download Token先消费后验证
**文件**: app/routes.py:274-295
**CWE**: CWE-691 (Insufficient Control Flow Management)
**来源**: A04 Insecure Design

`download_file_token()` L274先删除token (`db.session.delete(download_token)`), L282-285再读文件+解密, L288-291才做完整性校验。如果完整性校验失败→token已删除，用户无法重试。同时日志L277写"Token consumed"但token可能未被成功消费。

**影响**: 文件损坏时用户失去重试能力；操作不具备原子性
**修复**: 先校验完整性，再删除token：
```python
# 1. 解密+校验完整性
# 2. 如果通过，删除token
# 3. 如果失败，保留token让用户重试
db.session.commit()  # 确认删除在完整性通过之后
```

### F-008: 日志泄露用户信息
**文件**: app/routes.py:84-85, 129, 137, 145, 163-165, 182-183, 195-201, 215-219, 232-249, 256-277, 289-293, 305-306, 311-312, 337-338, 363-364, 384
**CWE**: CWE-532 (Insertion of Sensitive Information into Log File)
**来源**: A09 Security Logging

日志广泛记录user_id、email、filename、file_hash、token前缀等。例如：
- L84-85: `f'New user: id={new_user.id}, email={new_user.email}'` — 邮箱明文
- L165: `f'Computed SHA-256: {file_hash}'` — 文件哈希
- L305: `f'SHARE page hit for file_id={file_id} by user {current_user.id}'` — 用户操作关联

日志文件位于 `logs/app.log`，10MB轮转、5个备份。无访问控制→任何能读文件系统的人可获取完整用户行为日志。

**影响**: 用户隐私泄露、操作关联分析
**修复**: 日志中只记录user_id，不记录email。对文件名/hash做截断。

### F-009: 密码策略仅在前端验证
**文件**: app/templates/register.html:24-53, app/routes.py:76-78
**CWE**: CWE-602 (Client-Side Enforcement of Server-Side Security)
**来源**: A04 Insecure Design

密码强度在前端JS验证（register.html L24-29），服务端也调用`is_strong_password()`（L76）。但前端验证失败时`e.preventDefault()`阻止提交——如果攻击者绕过前端（curl/Postman直接POST），服务端会验证。不过服务端验证是在L76——这个逻辑是对的。

等等，L76: `if not is_strong_password(password): flash(...) return redirect(...)` — 服务端确实验证了。这不是漏洞。让我重新检查...

实际上密码策略是前+后端双重验证，这是正确的。撤回这个finding。

重新检查：L76的服务端验证正确。这不是medium，这是无问题。

### F-010: 文件扩展名验证仅检查后缀
**文件**: app/routes.py:21-22, 156
**CWE**: CWE-434 (Unrestricted Upload of File with Dangerous Type)
**来源**: A03 Injection

`allowed_file()` 只检查文件扩展名，不检查MIME类型或magic bytes。攻击者可将恶意.py文件重命名为 .txt → 通过验证 → 上传到服务器。虽然Fernet加密存储+不直接执行，但如果未来功能扩展（如文本预览直接输出内容），可能触发XSS或其他注入。

**影响**: 当前危害低（加密存储），但面向未来脆弱
**修复**: 添加MIME类型验证：
```python
import magic
mime = magic.from_buffer(file_content, mime=True)
if mime not in ALLOWED_MIME_TYPES:
    flash('Invalid file type')
```

---

## 🟢 LOW / INFO

### F-011: Fernet密钥硬依赖环境变量 — 无回退
**文件**: app/__init__.py:18-20
**CWE**: CWE-1404 (Missing Encryption of Sensitive Data)
**来源**: A02 Cryptographic Failures

`encryption_key = os.getenv('ENCRYPTION_KEY')` — 如果环境变量未设置，应用崩溃。无默认密钥或密钥生成逻辑。这在生产环境是正确的，但对开发/测试不友好。

### F-012: SECRET_KEY访问不一致
**文件**: app/__init__.py:18-24
**CWE**: CWE-1104 (Use of Unmaintained Third Party Components)
**来源**: A05 Security Misconfiguration

L19: `os.getenv('ENCRYPTION_KEY')` — 失败返回None
L24: `os.environ['FLASK_SECRET_KEY']` — 失败抛KeyError

两种不一致的env var访问模式。一个优雅、一个粗暴。如果部署者设置了ENCRYPTION_KEY但忘了FLASK_SECRET_KEY，会得到KeyError而非明确的错误消息。

### F-013: 无CSRF保护
**文件**: app/routes.py (所有POST路由), app/templates/*.html (所有表单)
**CWE**: CWE-352 (Cross-Site Request Forgery)
**来源**: A01 Broken Access Control

所有表单均无CSRF token。Flask-WTF未集成。攻击者可构造恶意页面，诱导认证用户执行非自愿操作（上传文件、分享文件、删除文件）。

由于应用使用session cookie认证 + SameSite默认=Lax，GET请求不会自动携带cookie跨站。但POST from form submission会触发SameSite=Lax。所以如果应用部署在同站上下文中，CSRF仍可能被利用。

### F-014: upload.html DOM-based XSS (自体XSS)
**文件**: app/templates/upload.html:65
**CWE**: CWE-79 (Cross-Site Scripting)
**来源**: A03 Injection

```javascript
filePreview.innerHTML = `...${file.name}...`
```

`file.name`来自用户自己选择的文件名。虽然需要用户选择恶意文件名，但如果攻击者能诱导用户选择特定文件（如通过社交工程），DOM XSS可执行。实际可利用性低——这是一类"自体XSS"。

### F-015: 无速率限制
**文件**: app/routes.py (全局缺失)
**CWE**: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
**来源**: A07 Identification Failures

虽然后端有账户锁定（5次/15min），但攻击者可针对所有用户发起登录尝试（每个账号4次，永不触发锁定）。大批量尝试仍可暴力破解弱密码。无IP级速率限制。

### F-016: host='0.0.0.0' + 443 端口
**文件**: run.py:39-40
**CWE**: N/A (配置选择)
**来源**: A05 Security Misconfiguration

绑定所有接口+特权端口(443)。多数生产环境会用反向代理(nginx)处理TLS。这不是漏洞本身但在debug模式下加剧风险。

---

## ✅ 已确认安全的设计

以下安全检查已正确实现，无漏洞：

1. **密码哈希**: pbkdf2:sha256, werkzeug安全实现 (models.py:29, routes.py:80)
2. **账户锁定**: 5次失败/15分钟，避免暴力破解 (routes.py:113-123)
3. **Fernet加密**: 文件上传前加密存储，密钥从环境变量 (__init__.py:18-22, routes.py:168-173)
4. **文件完整性**: SHA-256哈希存储+下载时比对 (routes.py:163, 214-221)
5. **Token安全**: secrets.token_urlsafe(32) 256位熵，10分钟过期，单次消费 (routes.py:242-247)
6. **secure_filename**: 清理文件名中的路径分隔符 (routes.py:157)
7. **密码强度**: 前后端双重验证 8+字符/大小写/数字/特殊字符 (routes.py:25-37, register.html:24-29)
8. **文件所有权**: delete_file, unshare_file 正确检查所有权 (routes.py:349-351, 373-376)
9. **download_file授权**: 检查所有权OR分享关系 (routes.py:199)
10. **自我分享防护**: share_file拒绝分享给自己 (routes.py:320-322)

---

## 统计

| 严重度 | 数量 | Finding IDs |
|--------|------|------------|
| CRITICAL | 3 | F-001, F-002, F-003 |
| HIGH | 3 | F-004, F-005, F-006 |
| MEDIUM | 4 | F-007, F-008, F-010, F-013 |
| LOW | 5 | F-011, F-012, F-014, F-015, F-016 |
| **总计** | **15** | |

### 按OWASP类别

| 类别 | 数量 |
|------|------|
| A01 Broken Access Control | 4 (F-002, F-004, F-013) |
| A02 Cryptographic Failures | 1 (F-011) |
| A03 Injection | 1 (F-010, F-014) |
| A04 Insecure Design | 3 (F-003, F-007) |
| A05 Security Misconfiguration | 4 (F-001, F-006, F-012, F-016) |
| A07 Authentication Failures | 2 (F-005, F-015) |
| A09 Logging Failures | 1 (F-008) |

### 每文件分布

| 文件 | Findings |
|------|----------|
| app/routes.py | F-002, F-003, F-004, F-005, F-006, F-007, F-008, F-010, F-013 |
| run.py | F-001, F-016 |
| app/__init__.py | F-011, F-012 |
| app/templates/upload.html | F-014 |
| app/models.py | 无 |
| init_db.py | 无 |
| 全局 | F-015 |

---

## 已知偏见声明

以下问题在审计前已通过代码预览发现，可能影响审计中立性：
- F-003 (文件名碰撞) — 审计前已知
- F-007 (token先消费后验证) — 审计前已知（token竞态）

审计过程中已努力平等审查所有代码区域，不因已知偏见而忽视其他漏洞类别。

---

*审计完成时间: 2026-07-10 | 审计者: Brain A (皮特)*
*下一阶段: findings_B (Codex盲审) → 仲裁差异 → 最终ground truth*
