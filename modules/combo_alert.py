#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块 6（L5）：组合行为告警 —— "读敏感路径 + 外联"

原理：单独读凭据或单独上网都可能是正常操作；真正的肉鸡信号是
     在同一会话的时间窗口内，先读凭据、再向外网发起请求。

只读 sessions/*.jsonl 的原始 function_call 记录：
  - 敏感读取：工具参数里的 file_path/path/pattern 命中敏感路径模式，
              或 shell 命令里出现明确的读取动词 + 敏感路径；
  - 外联事件：WebFetch/WebSearch 的 url/query，或 curl/wget/Invoke-WebRequest
              指向白名单外的 host。
不读取任何凭据文件内容，不打印完整命令或完整 URL，只给路径与 host。

输出 data/combo_alert.json。
"""
import json, os, pathlib, re, datetime, collections

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "combo_alert.json"
HOME = pathlib.Path.home()

DIRECT_READ_TOOLS = {"read", "write", "edit", "multiedit", "notebookedit", "glob", "grep"}
NET_TOOLS = {"webfetch", "websearch"}
CMD_TOOLS = {"bash", "powershell"}


def load_config():
    for name in ("config.json", "config.example.json"):
        p = ROOT / name
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                pass
    return {}


def expand(p):
    s = str(p)
    return pathlib.Path(str(HOME) + s[1:] if s.startswith("~") else s)


def display(s):
    return str(s).replace(str(HOME), "~")


def hosts_from(text):
    return [m.group(1).lower() for m in
            re.finditer(r"https?://([A-Za-z0-9.\-]+)", str(text))]


def main():
    cfg = load_config()
    sessions = expand(cfg.get("sessions_dir", "~/.workbuddy/projects"))
    allowed = set(h.lower() for h in cfg.get("allowed_egress_hosts", []))
    patterns = [re.compile(p, re.I) for p in cfg.get(
        "sensitive_path_patterns", [r"\.ssh[/\\]", "keyblob", r"\.aws[/\\]"])]
    window = int(cfg.get("combo_window_seconds", 300))

    # shell 中明确的读取动作 + 敏感路径（避免把"提到路径"当成"读了路径"）
    shell_read = re.compile(
        r"(?:cat|type|get-content|more|less|head|tail|open\s*\(|read(?:_file)?\s*\()"
        r"[^\n]{0,120}?(?:\.ssh[/\\]|id_(?:rsa|dsa|ecdsa|ed25519)|keyblob|\.aws[/\\]|\.netrc)",
        re.I)

    events = []          # (session_id, ts_ms, kind, tool, detail)
    total = 0
    if sessions.exists():
        for f in sessions.rglob("*.jsonl"):
            try:
                for line in f.open(encoding="utf-8", errors="ignore"):
                    if '"type":"function_call"' not in line and "'type': 'function_call'" not in line:
                        continue
                    try:
                        o = json.loads(line)
                    except Exception:
                        continue
                    total += 1
                    name = str(o.get("name", "")).lower()
                    args = o.get("arguments")
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except Exception:
                            args = {}
                    if not isinstance(args, dict):
                        continue
                    try:
                        ts = int(o.get("timestamp", 0))
                    except Exception:
                        ts = 0
                    sid = str(o.get("sessionId", ""))[:16]

                    # 敏感读取判定
                    hit = None
                    if name in DIRECT_READ_TOOLS:
                        for k in ("file_path", "path", "pattern", "file", "notebook_path"):
                            val = args.get(k)
                            if val and any(p.search(str(val)) for p in patterns):
                                hit = display(val)
                                break
                    elif name in CMD_TOOLS:
                        cmd = str(args.get("command", ""))
                        m = shell_read.search(cmd)
                        if m:
                            hit = display(m.group(0)[:100])
                    if hit:
                        events.append((sid, ts, "sensitive_read", name, hit))
                        continue   # 同一调用不再算作外联

                    # 外联判定
                    targets = []
                    if name in NET_TOOLS:
                        for k in ("url", "query"):
                            if args.get(k):
                                targets.append(str(args[k]))
                    elif name in CMD_TOOLS:
                        cmd = str(args.get("command", ""))
                        for m in re.finditer(r"(?:-uri|url|=)\s*[\"']?(https?://[^\"'\s]+)", cmd):
                            targets.append(m.group(1))
                        for m in re.finditer(r"\b(?:curl|wget)\s+(?:-[^\s]+\s+)*[\"']?(https?://[^\"'\s]+)", cmd):
                            targets.append(m.group(1))
                    for t in targets:
                        for h in hosts_from(t):
                            if h and h not in allowed and not h.endswith(".local"):
                                events.append((sid, ts, "egress", name, h))
            except Exception:
                continue

    events.sort(key=lambda e: (e[0], e[1]))
    by_session = collections.defaultdict(list)
    for e in events:
        by_session[e[0]].append(e)

    alerts = []
    for sid, seq in by_session.items():
        for i, ev in enumerate(seq):
            if ev[2] != "sensitive_read":
                continue
            for nxt in seq[i + 1:]:
                if nxt[2] != "egress":
                    continue
                gap = (nxt[1] - ev[1]) / 1000.0
                if 0 <= gap <= window:
                    alerts.append({
                        "session": sid,
                        "gap_seconds": round(gap, 1),
                        "read": {"tool": ev[3], "path": ev[4]},
                        "egress": {"tool": nxt[3], "host": nxt[4]},
                    })
                if nxt[1] - ev[1] > window * 1000:
                    break

    stats = {
        "function_calls_scanned": total,
        "sensitive_reads": sum(1 for e in events if e[2] == "sensitive_read"),
        "external_egress_events": sum(1 for e in events if e[2] == "egress"),
        "combo_alerts": len(alerts),
    }
    result = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "window_seconds": window,
        "stats": stats,
        "alerts": alerts[:50],
        "verdict": "ALERT" if alerts else ("PASS" if total else "REVIEW"),
        "note": "告警需人工复核：读包管理器配置后访问官方源等正常行为可能命中；只看原始记录，不读凭据内容。",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print("[combo] written:", OUT)
    print("[combo] calls:", total, "alerts:", len(alerts), "verdict:", result["verdict"])


if __name__ == "__main__":
    main()
