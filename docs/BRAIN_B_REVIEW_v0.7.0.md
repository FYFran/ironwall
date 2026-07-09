# 🔪 铁壁对抗审查：v0.7.0方案攻击

---

## 攻击点 1：HTML报告本身可能是不安全的交付物

**问题：单文件HTML报告包含漏洞代码片段，浏览器打开时可能触发攻击。**

设想扫描出一个Reflected XSS的finding，代码行是：
```go
w.Write([]byte("<script>" + userInput + "</script>"))
```

这段代码被原样嵌入HTML报告。浏览器打开报告文件时，`<script>`标签被解析执行。如果代码片段里还有更危险的payload（`<img onerror=fetch(...)>`、`<script>document.cookie</script>`），报告本身就是攻击载体。

**你的防御是什么？** 方案里一句没提HTML实体编码。4小时赶工最容易漏的就是这个——忙着做折叠动画和颜色主题，忘了`innerHTML`注入。

**Fix required：** 所有代码片段必须经过`textContent`/实体编码，不能走`innerHTML`。需要专门测试：用一个包含XSS payload的Go文件做扫描，确认报告里的代码片段不会执行。

---

## 攻击点 2：AI retry是治标——根因是batch架构不自洽

**79%失败率来自19 batch顺序调API。加2s间隔 = 38秒额外延迟，batch数一个没减。**

真正的问题是：为什么19个batch？如果一次扫描有100个findings，每个finding单独调AI，这意味着100次API调用。2s间隔后变成200秒。客户等得了吗？

**攻击向量：**
- 如果DeepSeek API的limit是每天X次调用（而非每秒），你的backoff策略完全无效——延迟到最后还是429。
- 方案没有提并发模型。如果有QPS限制，应该用token bucket + semaphore控制并发，不是纯顺序+间隔。
- 最根本的优化方向：合并小finding的prompt，一次API调用分析多个finding。这比backoff有效10倍。

**当前方案的结果：** 花了2小时，失败率从79%降到60%，仪式感做足，但用户体验仍然是"点击扫描→去泡杯咖啡→回来看结果"。

---

## 攻击点 3：gosec自定义规则只有sink检测，没有source追踪 = 装饰性规则

**Brain A承认"不走多文件taint追踪(太大)"。但跨函数数据流是SAST的核心能力，不是可选feature。**

你的AST visitor能看到这个：
```go
// 容易抓——sink和source在同一表达式
db.Query("SELECT * FROM users WHERE name='" + userInput + "'")
```

看不到这个：
```go
// file: query_builder.go
func buildUserQuery(input string) string {
    return fmt.Sprintf("SELECT * FROM users WHERE name='%s'", input)
}

// file: handler.go  
db.Query(buildUserQuery(req.FormValue("name")))
```

而现实世界的Go项目，代码封装至少一层。`db.Query(raw)` 99%的调用传的是变量而非字面拼接。你的规则只能抓"把source直接拼在sink旁边"的玩具漏洞——这种代码在正经项目里几乎不存在。

**后果：** 客户跑扫描，报告显示0个SQL注入。客户以为项目安全。实际上跨文件拼接的漏洞一个没抓到。你的铁壁在好项目上"不乱报"（0/23），不是因为精准，是因为**规则太浅探不到真正的漏洞**。不是低误报，是高漏报。

---

## 攻击点 4（bonus）：闲鱼渠道 = 品牌自杀

SAST产品买家是企业安全团队，采购决策链是：安全工程师评估→技术负责人审批→采购走流程。闲鱼是什么认知？"二手转卖"、"个人卖家"、"便宜货"。

在闲鱼挂listing卖SAST工具，第一印象不是"专业安全产品"，而是"个人开发者做的side project挂闲鱼碰运气"。品牌信任从0开始往下挖。

**这不影响v0.7.0的功能交付，但影响整个产品的生存。** 如果目标真的是商业化，频道应该是：GitHub开源→Product Hunt→安全社区（r/netsec、安全群）→独立官网。闲鱼可以作为一个边缘渠道存在，但不应该是主渠道。

---

## 总结判断

| 维度 | 评级 | 说明 |
|------|------|------|
| 方案可行性 | ⚠️ 能做但不专业 | 三条线技术上都能执行，但交付质量达不到商业SAST产品线 |
| HTML报告 | ⚠️ 方向对，隐患大 | 正向改进，但代码片段XSS风险和缺少SARIF导出是硬伤 |
| AI retry | ❌ 治标不治本 | 不改batch架构，backoff只是延迟失败。2h投入产出比低 |
| gosec规则 | ❌ 装饰性 | 无跨函数追踪=大量漏报。4h做15个规则质量不可控。false negative比false positive危险10倍 |
| 整体判断 | **不建议按此方案交付闲鱼客户** | 修完攻击点1+2+3后再发布，否则第一单就可能是最后一单 |

**如果只能修一个：修攻击点1（HTML XSS风险）。** 产品本身不能是不安全的，这是底线。