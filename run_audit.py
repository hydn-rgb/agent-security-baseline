#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agent-security-baseline 总控
依次运行四个只读审计模块，汇总成 data/summary.json。
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

if __name__ == "__main__":
    print("=== agent-security-baseline audit ===")
    summary = {"generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
               "modules": {}, "verdict": "PASS"}
    for m in MODULES:
        try:
            p = subprocess.run([sys.executable, str(ROOT / "modules" / m)],
                               capture_output=True, text=True, timeout=120)
            summary["modules"][m] = {"exit": p.returncode,
                                     "stdout": p.stdout.strip()[-500:],
                                     "stderr": p.stderr.strip()[-500:]}
            if p.returncode != 0:
                summary["verdict"] = "ERROR"
            print(f"  [{m}] exit={p.returncode}")
        except Exception as e:
            summary["modules"][m] = {"error": str(e)}
            summary["verdict"] = "ERROR"
    s = ROOT / "data" / "summary.json"
    s.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print("=== summary:", s, "verdict:", summary["verdict"], "===")
