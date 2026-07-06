# 用 Ironwall 赚钱 — 接单实战指南

## 🎯 策略

用 ironwall 跑 77ms 扫描 → 生成专业 Markdown 报告 → 卖给不懂安全的开发者。

成本：5 分钟/单。售价：¥100-300/单。一天做 3 单 = ¥300-900。

---

## 平台 1：Fiverr（最推荐，立刻能上）

**为什么这个：** 不需要审核，不需要实名，注册就卖。国际支付。

### 注册

1. 打开 https://fiverr.com
2. 点 Join → 用邮箱注册
3. 完善资料：头像 + 简介（用下面的模板）
4. 绑定收款：PayPal 或 Payoneer（申请免费 Payoneer 账户）

### 创建 3 个 Gig

#### Gig 1：代码安全审计（主打）

**Title:** I will audit your code for security vulnerabilities and give a detailed report

**Category:** Programming & Tech → Code Review

**Price:**
- Basic ($15): 1 file or <500 lines, security scan report
- Standard ($35): Full project <5000 lines, detailed report + fixes
- Premium ($75): Full codebase, 7-step audit, attack scenario analysis, priority fixes

**Description:**
```
I will run a professional 7-step security audit on your codebase and deliver a detailed report with:

- Secret/key scanning (API keys, tokens, passwords)
- SAST analysis (SQL injection, XSS, command injection)
- Hardcoded credential detection
- Dependency vulnerability check
- Server configuration review
- Database migration audit

You'll receive:
- Markdown report with all findings, severity levels, and CWE references
- Attack scenario analysis (who, how, impact)
- Concrete fix suggestions for each issue

I use Ironwall — an open-source 7-step audit CLI — combined with manual review. Your code never leaves my machine.

No AI-generated fluff. Every finding has a file path, line number, and code citation.

Not sure if this is right for you? Message me first.
```

#### Gig 2：Go 项目代码审查

**Title:** I will review your Go code for bugs, security issues and best practices

**Price:**
- Basic ($10): Quick review of 1 file
- Standard ($25): Review of small project + report
- Premium ($50): Full review with security audit

#### Gig 3：网站安全配置检查

**Title:** I will scan your website configuration for security misconfigurations

**Price:**
- Basic ($15): Docker/nginx/env check
- Standard ($30): Full config audit + database migration check

### 交付流程（关键！）

1. 客户下单，发源代码（zip 或 GitHub）
2. 本地解压，运行 `ironwall scan . --format markdown`
3. 花 2 分钟快速检查报告，去掉明显的假阳性
4. 对每个 CRITICAL/HIGH finding 手动写一句修复建议
5. 把报告发给客户

**实际工作时间：5-10 分钟。**

### 注意事项

- 不要接看起来是非法项目的单子（黑客工具、钓鱼网站等）
- 前 5 单可以亏本做（收 $5-10），拿好评
- 5 个好评后涨价到 $30-50
- 记得在报告加你的名字 + GitHub 链接（建口碑）

---

## 平台 2：程序员客栈（国内，客单价高）

**为什么这个：** 中文沟通，项目质量高，抽成低（10-15%）。

### 注册

1. 打开 https://proginn.com
2. 注册 → 实名认证（需要身份证）
3. 填写技术标签：Go, Python, 安全审计, 代码审查
4. 审核通过后开始接项目

### 服务描述模板

```
服务：专业代码安全审计

使用自研 7 步审计工具（GitHub 开源），对您的代码进行全方位安全检查：

1. 密钥泄露扫描（API Key、Token、密码）
2. SAST 静态分析（SQL 注入、XSS、命令注入）
3. 接口权限审计
4. 硬编码密钥检测
5. 依赖漏洞扫描
6. 服务器配置检查
7. 数据库迁移审计

交付物：
- 详细 Markdown 报告（含文件路径、行号、CWE 编号）
- 每个漏洞的攻击场景分析
- 具体修复方案

价格：¥200/次起（根据代码量浮动）
```

---

## 平台 3：Upwork（长期，单价最高）

海外自由职业平台，$30-100/小时。需要审核通过（比较严格）。

等你在 Fiverr 有 5 个好评之后再去申请。

---

## 操作流程图

```
接单 → 下载代码 → ironwall scan . --format markdown
  → 5 分钟人工 review → 发报告 → 收钱
```

**每单 5 分钟，售价 ¥100-300。一天 3 单 = ¥300-900。一个月 20 天 = ¥6000-18000。**

---

## 赚到第一单的行动计划

1. 🟢 **今天**：注册 Fiverr + 创建 3 个 Gig（15 分钟）
2. 🟢 **今天**：注册程序员客栈 + 提交认证（10 分钟）
3. 🟡 **2-3 天内**：Fiverr Gig 审核通过，开始接单
4. 🟡 **1 周内**：P0 价格拿到第一个好评
5. 🔵 **2 周内**：涨价到 $25-35，每天 1-2 单
6. 🔵 **1 月内**：程序员客栈第一单
