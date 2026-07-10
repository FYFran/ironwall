# NEXT_SESSION — 铁壁重启

> 2026-07-10 | 上次会话终点 | Brain B五刀扒光自欺

## 做了什么

6小时实战。4项目扫描(544~6826行)。AI引擎8轮迭代修复——从完全不可用到Precision 100%(actionable findings)。

## 核心真相（Brain B揭露）

1. **AI引擎是prompt分类器，不是审计引擎。** 调DeepSeek问"真的假的"→改severity。没有代码理解。
2. **Recall 7%才是真实水平。** 21个ground truth只检测到1.5个。
3. **v0.5.0设计全未实现。** OBSERVE→TRACE→VERIFY→ASSESS、攻击路径生成、上下文采集——代码零行。
4. **F1=0.568与Recall=7%数字不闭合。** 不同benchmark不同口径，需要审计。
5. **商业模型两头不靠。** 定价按产品(便宜)、成本按服务(贵)。

## 上次共识

**停写代码。先收集真实数据。**

1. 搞清楚AI失败的真正原因分布
2. 随机抽finding手动验证AI判断准确度
3. 定义真正"顶级"标准: 陌生人扫陌生项目，1h内找到≥1个真漏洞，≤5个FP
4. 基于真实数据写v0.6.0计划

## 关键文件

- `battle_test_candidates/FINAL_REPORT.md` — 完整报告
- `battle_test_candidates/RUN_001.md` — no-AI基线
- `battle_test_candidates/RUN_002.md` — AI引擎修复
- `battle_test_candidates/GROUND_TRUTH.md` — 21条ground truth
- `battle_test_candidates/EVAL_REPORT.md` — TP/FP/FN对照
- `docs/BRAIN_B_KNOWLEDGE.md` — 2025-2026 SAST/AI landscape数据
- `docs/BRAIN_B_REVIEW_BATTLETEST.md` — 初始Brain B攻击
- `docs/REVIEW_BATTLETEST.md` — Brain B共识

## 代码修改

- `internal/ai/engine.go` — 简化单阶段DeepVerify + 错误日志
- `internal/ai/client.go` — 新增ChatJSONWithMaxTokens
- `internal/ai/prompts.go` — 强化SystemPromptDeepVerify
- `internal/config/config.go` — AIDeepModel: chat替代reasoner
- `internal/config/defaults.go` — Version: 0.7.0

## 下一步（本次会话）

1. Brain A + Brain B收集最新SAST+AI研究数据
2. 基于数据讨论铁壁真正定位
3. 给出不吹牛逼的方案

## 提醒

- Codex proxy: `~/.codex-deepseek/src/main.py` port 4000
- DeepSeek key: `DEEPSEEK_API_KEY` env
- Brain B协议: `docs/BRAIN_B_PROTOCOL.md`
- 铁律: 不通过Brain B审查不写代码
