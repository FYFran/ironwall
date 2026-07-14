# LLM Wiki 自动化管道 (#41)

> 对话结束→提取知识→结构化Markdown→wiki/。知识不沉淀=每次对话从零开始。

## 管道：5阶段的自动化知识工程

```
对话结束 (Stop hook)
    │
    ▼
Phase 1: Knowledge Extraction
    ├── 提取: 关键决策、技术发现、失败教训、新工具/模式
    ├── 过滤: 去重（已有wiki内容）、去噪（日常闲聊）、去临时（一次性信息）
    └── 输出: [{topic, key_points, decision, rationale, code_refs, source_session}]
    
Phase 2: Topic Routing
    ├── AI安全 → wiki/ai-safety/
    ├── Harness工程 → wiki/harness-engineering/
    ├── Ironwall → wiki/ironwall/
    ├── Skill系统 → wiki/skills/
    ├── 方法论 → wiki/methodology/
    └── 新topic → 创建目录 + 更新INDEX.md

Phase 3: Structured Writing
    对每个提取项:
    ├── 查wiki/INDEX.md是否有相关页面
    ├── 有→追加到现有页面（更新/追加章节）
    ├── 无→创建新页面（模板：标题+日期+来源+内容+交叉引用）
    └── 所有新内容标记: <!-- source: session-YYYY-MM-DD -->

Phase 4: Cross-Reference
    ├── 扫描所有wiki文件找可链接的terms
    ├── 添加[[wikilink]]到相关页面
    └── 更新INDEX.md的"最近更新"部分

Phase 5: Quality Gate
    ├── 无hallucination检查（所有claims有source）
    ├── 无重复检查（新内容不复制已有）
    ├── 格式一致性（markdownlint）
    └── 通过→git add wiki/ → commit
```

## Stop Hook实现

```python
# .claude/hooks/lessons-extractor.py — Stop hook触发
# 每次会话结束自动运行

import json, os, re
from datetime import datetime
from pathlib import Path

WIKI_ROOT = Path("f:/ClaudeFiles/wiki")
INDEX_PATH = WIKI_ROOT / "INDEX.md"

TOPIC_ROUTES = {
    "ai.safety|prompt.injection|jailbreak|AI.护栏": "ai-safety",
    "harness|agent.framework|CLAUDE.md|hook|MCP|skill.system": "harness-engineering",
    "ironwall|SAST|MISSING|security.scanner|漏洞检测": "ironwall",
    "skill|轮回|forge|skill.优化|GEPA": "skills",
    "methodology|方法论|decision.framework|铁律|IVR": "methodology",
}

def extract_knowledge(transcript_path: str) -> list[dict]:
    """Phase 1: Extract structured knowledge from transcript."""
    # Read transcript
    # Identify decision points, technical findings, failures
    # Return structured items
    items = []
    # ... extraction logic ...
    return items

def route_topic(text: str) -> str:
    """Phase 2: Route content to wiki category."""
    for pattern, category in TOPIC_ROUTES.items():
        if re.search(pattern, text, re.IGNORECASE):
            return category
    return "general"

def write_wiki(category: str, item: dict, session_id: str):
    """Phase 3: Write structured markdown to wiki."""
    cat_dir = WIKI_ROOT / category
    cat_dir.mkdir(parents=True, exist_ok=True)
    
    # Check if related page exists
    page_name = slugify(item["topic"])
    page_path = cat_dir / f"{page_name}.md"
    
    if page_path.exists():
        # Append to existing
        with open(page_path, "a") as f:
            f.write(f"\n\n## Update: {datetime.now().strftime('%Y-%m-%d')}\n")
            f.write(f"<!-- source: {session_id} -->\n")
            f.write(f"{item['key_points']}\n")
    else:
        # Create new page
        with open(page_path, "w") as f:
            f.write(f"# {item['topic']}\n\n")
            f.write(f"**Created:** {datetime.now().strftime('%Y-%m-%d')}\n")
            f.write(f"**Source:** {session_id}\n\n")
            f.write(f"## Key Points\n\n{item['key_points']}\n\n")
            if item.get("decision"):
                f.write(f"## Decision\n\n{item['decision']}\n\n")
            if item.get("rationale"):
                f.write(f"## Rationale\n\n{item['rationale']}\n")
    
    # Update INDEX.md
    update_index(category, page_name, item["topic"])

def update_index(category: str, page_name: str, topic: str):
    """Phase 4: Update wiki index."""
    # Read existing INDEX.md
    # Add/update entry
    # Sort by date
    pass

def slugify(text: str) -> str:
    return re.sub(r'[^a-z0-9]+', '-', text.lower()).strip('-')
```

## 目录结构

```
wiki/
├── INDEX.md                          ← 总索引（按分类+日期）
├── ai-safety/
│   ├── prompt-injection-defense.md
│   ├── ai-output-filtering.md
│   └── model-jailbreak-patterns.md
├── harness-engineering/
│   ├── agent-framework-architecture.md
│   ├── hook-system-design.md
│   └── skill-lifecycle.md
├── ironwall/
│   ├── missing-detection-design.md
│   ├── benchmarks/
│   │   ├── owasp-benchmark-2026-07.md
│   │   └── ironwall-vs-semgrep-2026-07.md
│   └── architecture.md
├── skills/
│   ├── 轮回-v2.0-upgrade.md
│   ├── skill-optimization-patterns.md
│   └── gepa-methodology.md
└── methodology/
    ├── ivr-framework.md
    ├── brain-b-adversarial-review.md
    └── decision-framework.md
```

## 触发时机

1. **自动：** Stop hook — 每次会话结束
2. **手动：** `/wiki-extract` — 随时提取当前会话
3. **批量：** `python wiki-pipeline.py --since 2026-07-01` — 回溯历史会话

## 质量规则

| 规则 | 检查 |
|------|------|
| 无hallucination | 每项claim必须有source（文件名/行号/URL） |
| 去重 | 写入前检查已有wiki内容（语义相似度>0.8→合并不新增） |
| 压缩 | 不存原始对话。存提取后的结构化知识。 |
| 交叉引用 | 新内容必须链接到≥1个已有wiki页面 |
| 垃圾回收 | 每月检查：6个月未更新的页面→提议归档或删除 |
