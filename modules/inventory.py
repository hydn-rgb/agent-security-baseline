#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块 1：第三方工具清单
只读扫描 MCP 服务器 / skills / 客户端插件 / IDE 扩展 / 已安装 CLI。
never read 密钥内容：只取路径、名称、版本、更新时间等元数据。
输出 data/inventory.json。
"""
import json, os, pathlib, datetime

WB = pathlib.Path(os.environ.get("USERPROFILE", "")) / ".workbuddy"
OUT = pathlib.Path(__file__).resolve().parents[1] / "data" / "inventory.json"


def safe_list(p):
    try:
        return sorted(x.name for x in pathlib.Path(p).iterdir() if not x.name.startswith("."))
    except Exception:
        return []


def main():
    now = datetime.datetime.now().isoformat(timespec="seconds")
    result = {"generated_at": now, "sources": {}}

    # MCP 服务器（只取名字与键集合，不打印任何 value）
    try:
        mcp = json.loads((WB / "mcp.json").read_text(encoding="utf-8"))
        result["sources"]["mcp_servers"] = list(mcp.get("mcpServers", {}).keys())
    except Exception as e:
        result["sources"]["mcp_servers"] = f"ERR:{type(e).__name__}"

    # 用户 skills（名称清单）
    result["sources"]["user_skills"] = safe_list(WB / "skills")
    result["sources"]["skills_count"] = len(result["sources"]["user_skills"])

    # 插件缓存（只取目录名）
    result["sources"]["plugin_cache"] = safe_list(WB / "plugins" / "cache" / "workbuddy-builtin")[:60]

    # IDE 扩展
    for d in [pathlib.Path(os.environ.get("USERPROFILE", "")) / ".vscode" / "extensions",
              pathlib.Path(os.environ.get("USERPROFILE", "")) / ".cursor" / "extensions"]:
        if d.exists():
            result["sources"]["ide_extensions"] = safe_list(d)

    # 常见 AI CLI（只探测可执行文件是否存在）
    import shutil
    result["sources"]["cli_present"] = {
        n: bool(shutil.which(n)) for n in
        ["code", "cursor", "opencode", "claude", "gemini", "gh", "git", "docker", "python", "node"]
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print("[inventory] written:", OUT)
    print("[inventory] mcp:", result["sources"]["mcp_servers"])
    print("[inventory] skills_count:", result["sources"]["skills_count"])


if __name__ == "__main__":
    main()
