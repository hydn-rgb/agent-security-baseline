#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块 4：定期扫全团队仓库的 remote
对应 ZCode 事件的自查动作：找出 .git/config 里陌生 remote。
只读：调用 git remote -v，不修改任何仓库配置。
输出 data/remote_scan.json。
"""
import json, os, pathlib, subprocess, datetime, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "remote_scan.json"

def _cfg():
    """配置从 config.json（优先）/ config.example.json 读取；命令行参数优先级最高。"""
    for name in ("config.json", "config.example.json"):
        p = ROOT / name
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                pass
    return {}


_CFG = _cfg()
# 默认扫描根；可通过命令行参数覆盖，支持多根
DEFAULT_ROOTS = [str(pathlib.Path(x).expanduser()) for x in
                 _CFG.get("scan_roots", ["~/projects"])]
SKIP_DIRS = {".git", "node_modules", ".cache", "site-packages", "blobs",
             "__pycache__", ".workbuddy", "venv", ".venv"}
# 允许的 remote 主机关键字（按你的实际团队改）
TRUSTED_HOST_HINTS = _CFG.get("trusted_remote_host_hints",
                              ["github.com", "gitee.com", "gitlab", "coding.net"])


def find_repos(roots, max_depth=5, limit=300):
    seen, repos = set(), []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dp, dn, fn in os.walk(root):
            dn[:] = [d for d in dn if d not in SKIP_DIRS]
            depth = dp[len(root):].count(os.sep)
            if ".git" in fn and depth <= max_depth and dp not in seen:
                seen.add(dp)
                repos.append(dp)
            if len(repos) >= limit:
                return repos
    return repos


def main():
    roots = sys.argv[1:] or DEFAULT_ROOTS
    repos = find_repos(roots)
    rows, suspicious = [], []
    for r in repos:
        try:
            p = subprocess.run(["git", "-C", r, "remote", "-v"],
                               capture_output=True, text=True, timeout=8)
            lines = [l.strip() for l in p.stdout.splitlines() if l.strip()]
        except Exception as e:
            lines = [f"ERR:{type(e).__name__}"]
        if not lines:
            continue
        for line in lines:
            parts = line.split()
            host = parts[1] if len(parts) > 1 else ""
            trusted = any(h in host.lower() for h in TRUSTED_HOST_HINTS)
            rows.append({"repo": r, "remote": line[:200], "host": host,
                         "trusted_hint": trusted})
            if not trusted:
                suspicious.append({"repo": r, "host": host})

    result = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "scan_roots": roots,
        "repos_found": len(repos),
        "repos_with_remote": len({x["repo"] for x in rows}),
        "remote_lines": rows,
        "suspicious": suspicious,
        "verdict": "PASS" if not suspicious else "REVIEW",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print("[remote] written:", OUT)
    print("[remote] repos:", len(repos), "with remote:", result["repos_with_remote"],
          "suspicious:", len(suspicious))


if __name__ == "__main__":
    main()
