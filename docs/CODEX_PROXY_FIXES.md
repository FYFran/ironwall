# Codex Proxy Fixes — Brain B Web Search Enablement

> 2026-07-10 | 6 fixes applied to `~/.codex-deepseek/src/main.py`

## Summary

Enabled `tavily_search` tool for Brain B (Codex + DeepSeek local proxy) so it can independently search the web in real-time.

## Fixes Applied

### 1. Force non-stream when tools present (line ~420)
```python
if chat_body.get("tools"):
    stream = False
    chat_body["stream"] = False
```
**Why:** Tool call loop (`_handle_non_stream`) only works in non-stream mode. Codex sends `stream:true` by default but the proxy needs `stream:false` to execute tool calls.

### 2. Inject tavily_search tool (line ~166)
```python
if not has_tavily:
    tools.append({"type": "function", "function": {"name": "tavily_search", ...}})
```
**Why:** Codex doesn't include `tavily_search` in its tool list (it's an MCP tool that Codex's router rejects). Proxy injects it so DeepSeek knows it can call it.

### 3. Dedup check before injection (line ~162)
```python
has_tavily = any(t.get("function", {}).get("name") == "tavily_search" for t in tools)
```
**Why:** If Codex ever DOES send tavily_search (via MCP), injection would cause "Tool names must be unique" error.

### 4. Tool call loop handles tavily variants (line ~470)
```python
if func_name in ("web_search", "tavily_search") or "tavily_search" in func_name:
```
**Why:** Handles bare `tavily_search` and MCP-namespaced `mcp__tavily__tavily_search`.

### 5. SSE response protocol (line ~319)
```python
def _json_response_as_sse(self, data, status=200):
    # Emits: response.created → response.in_progress →
    #   response.output_item.added → response.content_part.added →
    #   response.output_text.delta (many) → response.content_part.done →
    #   response.output_text.done → response.output_item.done →
    #   response.completed → done [DONE]
```
**Why:** Codex expects SSE (Server-Sent Events) for `/v1/responses`. Non-stream handler produces JSON which Codex can't consume directly.

### 6. Codex config: disable built-in web_search
```toml
# ~/.codex/config.toml
web_search = "disabled"
```
**Why:** Codex's built-in web_search tool is rejected by the custom provider router. Disabling it avoids errors.

## Verification

```bash
# Restart proxy
taskkill //F //IM python.exe
cd ~/.codex-deepseek && nohup uv run python -m src.main > /tmp/codex_proxy.log 2>&1 &

# Test
codex exec -m deepseek --sandbox danger-full-access "Search tavily: ..."
```

**Zero errors confirmed:** `grep -c ERR /tmp/codex_proxy.log` → 0
**Real API calls:** Tavily returns 2896-4902 chars per search, DeepSeek generates 176-603 tokens output.
**Autonomous search:** Brain B decides on its own when to search, no prompt engineering needed.

## Environment

- TAVILY_API_KEY in `~/.codex-deepseek/.env` (dev key, needs refresh periodically)
- DeepSeek API key in `~/.codex-deepseek/.env` as `api_key`
