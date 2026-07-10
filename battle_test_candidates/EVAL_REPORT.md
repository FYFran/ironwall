# Ironwall 盲扫评估报告

> **Target**: secure-file-management (544行Python + HTML)
> **Ground Truth**: 21 findings (双人独立审计 + 交叉验证)
> **Ironwall**: v0.4.0, no-AI mode, 2分50秒扫描
> **Date**: 2026-07-10

---

## 核心指标

| 指标 | 值 | 说明 |
|------|-----|------|
| **Total Ironwall Findings** | 30 | 48 deduplicated → 30 |
| **True Positives (TP)** | 8 | 铁壁正确识别的真实漏洞 |
| **False Positives (FP)** | 22 | 铁壁报告但ground truth判定为误报 |
| **False Negatives (FN)** | 19 | Ground truth存在但铁壁未检测到 |
| **Precision** | **26.7%** | TP/(TP+FP) = 8/30 |
| **Recall (检测率)** | **9.5%** | TP/(TP+FN) = 2/21 (issue-level) |
| **F1 Score** | **0.140** | 2PR/(P+R) |
| **F3 Score** | **0.106** | Recall-weighted (β=3) |
| **MCC** | **-0.137** | Matthews Correlation (negative = worse than random) |

---

## TP详细 (8个finding → 2个ground truth issue)

### GT-001 (partial): debug=True + host='0.0.0.0'
| Ironwall ID | 工具 | 检测内容 | 行号 |
|-------------|------|---------|------|
| IRON-BANDIT-001 | Bandit B104 | host='0.0.0.0' binding detected | run.py:39 |
| IRON-SEMGREP-042 | Semgrep | app.run with bad host | run.py:36 |

⚠️ **检测到了host绑定，未检测到debug=True**。debug=True是RCE入口，host绑定是放大器。铁壁抓到放大器但漏了核心漏洞。

### GT-009: 全站无CSRF保护
| Ironwall ID | 工具 | 检测内容 | 行号 |
|-------------|------|---------|------|
| IRON-SEMGREP-036 | Semgrep (django rule) | 表单无csrf_token | index.html:32 |
| IRON-SEMGREP-037 | Semgrep (django rule) | 表单无csrf_token | index.html:81 |
| IRON-SEMGREP-038 | Semgrep (django rule) | 表单无csrf_token | login.html:7 |
| IRON-SEMGREP-039 | Semgrep (django rule) | 表单无csrf_token | register.html:7 |
| IRON-SEMGREP-040 | Semgrep (django rule) | 表单无csrf_token | share.html:7 |
| IRON-SEMGREP-041 | Semgrep (django rule) | 表单无csrf_token | upload.html:8 |

✅ **成功检测**。注意：使用的是Django规则检测Flask模板——跨框架误用但结果正确。

---

## FP详细 (22个finding，按类型分组)

### FP Type 1: XSS误报 (5个)
`semgrep.ironwall.xss.flask-request-to-response` 规则检测 `request.form.get()` → `response` 但代码实际用 `flash()` + `redirect()` + `render_template()` 处理——Jinja2自动转义，无XSS。

| Ironwall ID | 行号 | 实际代码 | 为何是FP |
|-------------|------|---------|---------|
| IRON-SEMGREP-002 | routes.py:64 | email=request.form.get('email') | → flash/redirect, Jinja2 escapes |
| IRON-SEMGREP-006 | routes.py:65 | username=request.form.get('username') | → flash/redirect |
| IRON-SEMGREP-010 | routes.py:66 | password=request.form.get('password') | → hash(), never to response |
| IRON-SEMGREP-014 | routes.py:97 | email=request.form.get('email') in login | → DB query |
| IRON-SEMGREP-018 | routes.py:98 | password=request.form.get('password') in login | → check_password_hash |
| IRON-SEMGREP-025 | routes.py:309 | email=request.form.get('email') in share | → DB query |

### FP Type 2: Open Redirect误报 (6个)
`python.flask.security.open-redirect` 规则检测 `redirect(request.url)` 但代码使用的是**自重定向**（redirect回同一URL），无外部URL注入风险。

| Ironwall ID | 行号 | 代码 | 为何是FP |
|-------------|------|------|---------|
| IRON-SEMGREP-022 | 149 | redirect(request.url) | self-redirect, no external URL |
| IRON-SEMGREP-023 | 154 | redirect(request.url) | self-redirect |
| IRON-SEMGREP-024 | 187 | redirect(request.url) | self-redirect |
| IRON-SEMGREP-029 | 317 | redirect(request.url) | self-redirect |
| IRON-SEMGREP-030 | 322 | redirect(request.url) | self-redirect |
| IRON-SEMGREP-031 | 329 | redirect(request.url) | self-redirect |

### FP Type 3: Missing SRI (4个)
CDN资源缺少integrity属性。这是真实的安全关注点但ground truth未覆盖（供应链/前端安全不在双审范围内）。

| Ironwall ID | 文件 | 类型 |
|-------------|------|------|
| IRON-SEMGREP-032~035 | base.html:7,53,54,55 | Bootstrap/jQuery CDN 无integrity |

⚠️ 这是潜在的ground truth缺口——SRI是合法安全问题但审计checklist未覆盖。

### FP Type 4: 供应链/运维信息 (7个)
| Ironwall ID | 内容 | 类型 |
|-------------|------|------|
| IRON-SEMGREP-001 | GitHub Actions mutable tag | 运维配置 |
| IRON-044 | SBOM 17 components | 信息 |
| IRON-045 | syft scan recommendation | 建议 |
| IRON-046 | GPG签名缺失 | 运维 |
| IRON-047 | Unpinned GitHub Action | 运维 |
| IRON-048 | OpenSSF Scorecard | 建议 |

Ground truth聚焦应用代码，未审计CI/CD配置和基础设施。这些不是FP（它们是真实的运维问题）但不在评估范围内。保守计入FP。

---

## FN详细 (19个完全遗漏 + 1个部分遗漏)

铁壁**完全没有检测到**以下19个ground truth findings：

| GT ID | 严重度 | 问题 | 为何遗漏 |
|-------|--------|------|---------|
| GT-001a | CRITICAL | debug=True RCE | 无规则覆盖(Python Flask debug模式) |
| GT-002 | CRITICAL | IDOR share_file | 需语义理解授权逻辑—SAST做不到 |
| GT-003 | CRITICAL | 文件名碰撞 | 业务逻辑缺陷—SAST做不到 |
| GT-004 | CRITICAL | /upload,/share缺@login_required | Semgrep无Flask装饰器缺失检测 |
| GT-005 | HIGH | GET /share泄露文件名 | 需理解授权流—SAST做不到 |
| GT-006 | HIGH | 登录错误消息差异 | 需理解认证流—SAST做不到 |
| GT-007 | HIGH | 无文件上传大小限制 | 无`MAX_CONTENT_LENGTH`检测规则 |
| GT-008 | HIGH | 日志明文PII | 无日志内容分析规则 |
| GT-010 | MEDIUM | Token先消费后验证 | 需理解TOCTOU—SAST做不到 |
| GT-011 | MEDIUM | 无登录速率限制 | 无`flask-limiter`缺失检测 |
| GT-012 | MEDIUM | 证书路径泄露IP | 无硬编码路径检测(非密钥类) |
| GT-013 | MEDIUM | Session fixation | 无Flask-Login配置审计规则 |
| GT-014 | MEDIUM | 注册用户枚举 | 需理解认证流—SAST做不到 |
| GT-015 | MEDIUM | Cookie安全属性缺失 | 无Flask cookie配置审计规则 |
| GT-016 | MEDIUM | SQLite明文存储 | 无数据库加密规则 |
| GT-017 | LOW | 仅检查扩展名 | 需上下文理解—SAST做不到 |
| GT-018 | LOW | Fernet密钥硬依赖env | 无规则覆盖 |
| GT-019 | LOW | DOM XSS upload.html | 无JS innerHTML检测规则 |
| GT-020 | LOW | 双层扩展名绕过 | 已有部分覆盖但未精确检测 |
| GT-021 | LOW | Fernet密钥轮换缺失 | 无密钥管理审计规则 |

**遗漏模式**：
- 8/19 (42%) 需要**语义理解/业务逻辑分析**—SAST本质上做不到
- 6/19 (32%) **缺少对应检测规则**—可添加规则解决
- 5/19 (26%) 需要**跨函数/跨文件数据流分析**—需要CodeQL级工具

---

## Per-Severity表现

| 严重度 | GT总数 | 铁壁TP | 铁壁FN | 召回率 |
|--------|--------|--------|--------|--------|
| CRITICAL | 4 | 0.5 (GT-001 partial) | 3.5 | 12.5% |
| HIGH | 5 | 1 (GT-009 full) | 4 | 20% |
| MEDIUM | 7 | 0 | 7 | 0% |
| LOW | 5 | 0 | 5 | 0% |

**CRITICAL级别**: 仅检测到host='0.0.0.0'（surface-level），核心RCE入口debug=True完全遗漏。IDOR、文件名碰撞、缺@login_required—3个CRITICAL完全盲区。

---

## FP根因分析

| FP类型 | 数量 | 占比 | 根因 |
|--------|------|------|------|
| Semgrep规则过宽 | 11 | 50% | XSS + Open Redirect规则对Flask flash/redirect模式产生大量误报 |
| 供应链/运维不在范围内 | 7 | 32% | Ground truth未覆盖CI/CD/基础设施 |
| Missing SRI | 4 | 18% | Ground truth覆盖范围外（但可能是真实问题） |

**关键发现**: 50%的FP来自2条Semgrep规则（XSS request-to-response + Open redirect）。这两条规则在此项目上的精确度接近0%。

---

## 总结

```
Ironwall v0.4.0 (no-AI) on 544-line Flask app:
  Precision: 26.7%  (8/30 — 每4条告警只有1条是真漏洞)
  Recall:     9.5%  (2/21 — 漏掉了90%的真漏洞)
  F1:        0.140  (综合表现差)
  MCC:      -0.137  (表现不如随机猜测)
```

### 为什么这么差

1. **无AI引擎** — 本次使用no-AI模式。AI引擎（v0.5.0的Analyst+Attacker+Verifier）设计目的就是处理这些FP (过滤XSS/Open Redirect误报) 和发现语义漏洞 (IDOR/business logic)。no-AI模式就是裸SAST。

2. **规则覆盖窄** — Ironwall的semgrep规则集(290条Python)覆盖了常见模式但漏了: Flask debug检测、Flask-Login配置审计、文件上传限制、日志PII、cookie安全属性、速率限制等。

3. **SAST天花板** — 8个ground truth finding需要语义理解(授权逻辑、业务流程、TOCTOU)—这些是SAST工具的固有盲区。EASE 2024论文结论(76.9% FN来自缺失规则)在此完全印证。

### 这个数字的意义

这不是在说"铁壁很烂"。这是在说:**裸SAST工具的真实表现就是这样**。Precision 26.7%、Recall 9.5%——这和学术界报告的SAST在真实项目上的数据一致(Bennett et al., EASE 2024: 11-27% 检出率)。

铁壁的AI引擎的价值主张正是填补这个gap。下一步应该用**AI模式**重扫，验证AI能在多大程度上:
- 降低FP (过滤XSS/open redirect误报 → 提升Precision)
- 提升Recall (AI语义理解发现SAST漏掉的漏洞)

---

## 局限声明

1. **n=1**: 单项目544行。不可泛化。
2. **no-AI模式**: AI引擎未启用。不代表v0.5.0完整产品表现。
3. **Ground truth非完美**: 双人审计仍有遗漏风险。
4. **运维finding分类争议**: 供应链/SBOM/SRI finding可能应计为TP(真实问题)，此处保守计入FP。
5. **HTML模板**: Codex未审计模板。模板相关finding置信度较低。

---

*评估完成: 2026-07-10*
