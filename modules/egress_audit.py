#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块 2：出站 HTTP 审计
目的：把"出网默认拒绝"策略落成可复核的配置证据 + 运行期外联取样。
只读：读取配置布尔与 trustedOrigins 主机名；不读取 token/密钥值。
取样：从会话原始记录提取曾被访问的 host，统计白名单外域名。
输出 data/egress_audit.json。
"""
import json, os, pathlib, re, datetime, collections

WB = pathlib.Path(os.environ.get("USERPROFILE", "")) / ".workbuddy"
ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "egress_audit.json"

DEFAULT_OK = {"127.0.0.1", "localhost", "::1"}


def load_allowed():
    """从 config.json（优先）或 config.example.json 读取允许域；
    不把本机内网地址、业务域名写进开源代码。"""
    for name in ("config.json", "config.example.json"):
        p = ROOT / name
        if p.exists():
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
                return set(h.lower() for h in d.get("allowed_egress_hosts", []))
            except Exception:
                pass
    return set()


def load_json(p):
    try:
        return json.loads(pathlib.Path(p).read_text(encoding="utf-8"))
    except Exception:
        return {}


def main():
    ok = DEFAULT_OK | load_allowed()
    settings = load_json(WB / "settings.json")
    failover = load_json(WB / "failover.json")
    sb = settings.get("sandbox", {})
    trusted = failover.get("trustedOrigins", [])

    # 从历史会话记录里抽取 host 出现频次（只读，不打印完整 URL 与参数）
    hosts = collections.Counter()
    projects = WB / "projects"
    # 只统计真正发起网络请求的调用参数：WebFetch/WebSearch 的 url/query，
    # 以及 Bash/PowerShell 命令里 invoke-webrequest -uri / curl 的目标。
    # 不扫描 Write/Edit 写入的文件内容 —— 否则训练样本里的示例 URL 会造成误报。
    NET_TOOLS = {"webfetch", "websearch"}
    CMD_TOOLS = {"bash", "powershell"}
    if projects.exists():
        for f in projects.rglob("*.jsonl"):
            try:
                for line in f.open(encoding="utf-8", errors="ignore"):
                    if '"type":"function_call"' not in line and "'type': 'function_call'" not in line:
                        continue
                    try:
                        o = json.loads(line)
                    except Exception:
                        continue
                    name = str(o.get("name", "")).lower()
                    args = o.get("arguments")
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except Exception:
                            args = {}
                    if not isinstance(args, dict):
                        continue
                    targets = []
                    if name in NET_TOOLS:
                        for k in ("url", "query"):
                            if args.get(k):
                                targets.append(str(args[k]))
                    elif name in CMD_TOOLS:
                        cmd = str(args.get("command", ""))
                        for m in re.finditer(r'(?:-uri|url|=)\s*["\']?(https?://[^"\'\s]+)', cmd):
                            targets.append(m.group(1))
                        for m in re.finditer(r'\b(?:curl|wget)\s+(?:-[^\s]+\s+)*["\']?(https?://[^"\'\s]+)', cmd):
                            targets.append(m.group(1))
                    for t in targets:
                        for m in re.finditer(r'https?://([A-Za-z0-9.\-]+)', t):
                            hosts[m.group(1).lower()] += 1
            except Exception:
                continue

    external = {h: n for h, n in hosts.items()
                if h and h not in ok and not h.endswith(".local")}

    result = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "policy": {
            "sandbox_networkDenyAllMigrated": sb.get("networkDenyAllMigrated"),
            "http_proxy": "<set>" if settings.get("http", {}).get("proxy") else "<empty>",
            "trustedOrigins_count": len(trusted),
        },
        "observed_hosts_top20": dict(hosts.most_common(20)),
        "external_hosts_not_in_baseline": dict(sorted(external.items(), key=lambda x: -x[1])[:30]),
        "verdict": "PASS" if sb.get("networkDenyAllMigrated") is True else "REVIEW",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print("[egress] written:", OUT)
    print("[egress] deny-all:", result["policy"]["sandbox_networkDenyAllMigrated"])
    print("[egress] external hosts:", len(external))


if __name__ == "__main__":
    main()
