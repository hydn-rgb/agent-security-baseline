#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agent-security-baseline 统一入口（one project, one command）

把六个只读审计模块缝合成：一次运行、一个聚合结论、一份人类可读汇总。
  python run_audit.py
每个模块产出 data/<模块>.json；本入口读取各模块的 verdict 聚合为总判定，
杜绝"子模块 REVIEW、总控却报 PASS"的掩盖问题。

安全约束（硬编码）：不读取/复制/写入任何密钥、token、凭证文件内容；
所有模块只取元数据与配置位，发现问题只报路径不报值。
"""
import json, subprocess, sys, pathlib, datetime

ROOT = pathlib.Path(__file__).resolve().parent
MODULES = [
    "inventory.py",             # L2 第三方工具清单
    "egress_audit.py",          # L4 出站 HTTP 审计
    "secret_isolation.py",      # L3 涉密隔离
    "remote_scan.py",           # 团队仓库 remote
    "credential_hygiene.py",    # L3 凭据卫生与移出清单
    "combo_alert.py",           # L5 读凭据+外联 组合告警
]
# 严重度排序：总判定取各模块中最严重者
SEVERITY = {"PASS": 0, "REVIEW": 1, "ALERT": 2, "ERROR": 3}


def aggregate(verdicts):
    """取最严重的 verdict 作为总判定。"""
    if not verdicts:
        return "ERROR"
    return max(verdicts, key=lambda v: SEVERITY.get(v, 0))


def main():
    print("=== agent-security-baseline audit (6 modules) ===")
    summary = {"generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
               "modules": {}, "verdict": "PASS"}
    md = ["# 安全基线审计汇总", "",
          f"生成时间：{summary['generated_at']}", "",
          "| 模块 | 层 | exit | verdict | 关键指标 |",
          "|---|---|---|---|---|"]
    layer = {"inventory.py": "L2", "egress_audit.py": "L4", "secret_isolation.py": "L3",
             "remote_scan.py": "—", "credential_hygiene.py": "L3", "combo_alert.py": "L5"}

    for m in MODULES:
        try:
            p = subprocess.run([sys.executable, str(ROOT / "modules" / m)],
                               capture_output=True, text=True, timeout=120)
            entry = {"exit": p.returncode, "stdout": p.stdout.strip()[-500:],
                     "stderr": p.stderr.strip()[-500:], "verdict": "ERROR"}
            # 读取模块产出json，提取其 verdict 与关键指标
            # inventory.py 是纯清单模块、不产风险判定，无 verdict 视为 PASS
            out = ROOT / "data" / (m.replace(".py", ".json"))
            if out.exists():
                try:
                    d = json.loads(out.read_text(encoding="utf-8"))
                    entry["verdict"] = d.get("verdict", "PASS" if m == "inventory.py" else "ERROR")
                    entry["key"] = {
                        "egress_audit.py": f"白名单外host={len(d.get('external_hosts_not_in_baseline', {}))}",
                        "credential_hygiene.py": f"高风险可达={d.get('high_risk_reachable_count')}",
                        "combo_alert.py": f"告警={d.get('stats', {}).get('combo_alerts')}",
                        "remote_scan.py": f"可疑remote={len(d.get('suspicious', []))}",
                        "secret_isolation.py": f"风险写白名单={len(d.get('risky_allow_entries', []))}",
                    }.get(m, "—")
                except Exception:
                    pass
            if p.returncode != 0:
                entry["verdict"] = "ERROR"
            summary["modules"][m] = entry
            print(f"  [{m}] exit={p.returncode} verdict={entry['verdict']}")
            key = entry.get("key", "—")
            md.append(f"| {m} | {layer.get(m,'—')} | {p.returncode} | {entry['verdict']} | {key} |")
        except Exception as e:
            summary["modules"][m] = {"error": str(e), "verdict": "ERROR"}
            print(f"  [{m}] ERROR {e}")
            md.append(f"| {m} | {layer.get(m,'—')} | — | ERROR | {e} |")

    summary["verdict"] = aggregate([v.get("verdict", "ERROR") for v in summary["modules"].values()])
    data = ROOT / "data"
    data.mkdir(parents=True, exist_ok=True)
    (data / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    md += ["", f"**总判定：{summary['verdict']}**", "",
           "> 总判定取六个模块中最严重者；PASS 仅表示全部模块无异常，不等于环境无缺口。"]
    (data / "summary.md").write_text("\n".join(md), encoding="utf-8")
    print(f"=== verdict: {summary['verdict']} ===")
    print("=== summary:", data / "summary.json", "|", data / "summary.md", "===")


if __name__ == "__main__":
    main()
