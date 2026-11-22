#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块 5（L3）：凭据卫生与移出检查

硬约束：只取元数据（存在性 / 目录条目名 / 文件大小 / 权限位），
      绝不 open() 任何凭据文件内容，绝不复制、打印、上传密钥值。

输出 data/credential_hygiene.json：
  - 凭据路径是否处于 agent 同用户可达范围
  - 沙箱写白名单是否误放行敏感路径
  - 当前权限档位是否放大了可达性
  - 一份可手动执行的移出清单（只给步骤，不自动执行）
"""
import json, os, pathlib, datetime

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "credential_hygiene.json"
HOME = pathlib.Path.home()


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
    if s.startswith("~"):
        s = str(HOME) + s[1:]
    return pathlib.Path(s)


def display(p):
    """路径脱敏：home 前缀折叠为 ~，不暴露账户名。"""
    s = str(p)
    try:
        if s.lower().startswith(str(HOME).lower()):
            s = "~" + s[len(str(HOME)):]
    except Exception:
        pass
    return s.replace(str(HOME), "~")


def main():
    cfg = load_config()
    wb = expand(cfg.get("workbuddy_dir", "~/.workbuddy"))
    paths = [expand(x) for x in cfg.get("credential_paths", [])]

    findings = []
    for p in paths:
        item = {"path": display(p), "exists": p.exists()}
        if p.exists():
            try:
                if p.is_dir():
                    names = sorted(x.name for x in p.iterdir())
                    item["type"] = "dir"
                    item["entry_count"] = len(names)
                    # 只看文件名，判断是否是疑似私钥；从不读取内容
                    item["key_candidates"] = [n for n in names
                                              if n.startswith("id_") and ".pub" not in n][:12]
                else:
                    item["type"] = "file"
                    item["size_bytes"] = p.stat().st_size
            except Exception as e:
                item["error"] = type(e).__name__
        # 同用户进程可达：fullAccess/默认档位下，用户目录内的文件均可被读
        item["agent_reachable"] = bool(p.exists()) and str(p).lower().startswith(str(HOME).lower())
        item["risk"] = ("HIGH" if item["agent_reachable"] and
                        (item.get("key_candidates") or p.name.lower() in
                         ("keyblob", "security", ".netrc", ".aws", ".ssh"))
                        else ("MEDIUM" if item["agent_reachable"] else "LOW"))
        findings.append(item)

    # 沙箱写白名单是否误放行
    allow = []
    try:
        settings = json.loads((wb / "settings.json").read_text(encoding="utf-8"))
        allow = settings.get("sandbox", {}).get("extraAllowWrite", [])
    except Exception:
        pass
    risky_allow = [display(x) for x in allow
                   if any(k in str(x).lower() for k in
                          (".ssh", ".aws", "keyblob", "credential", "token", "secret"))]

    # 权限档位（只从数据库读 permission_mode 字段，不碰其他表内容）
    perm = None
    try:
        import sqlite3
        db = wb / "workbuddy.db"
        if db.exists():
            con = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)
            cols = [r[1] for r in con.execute("PRAGMA table_info(automations)")]
            if "permission_mode" in cols:
                perm = con.execute("SELECT permission_mode FROM automations LIMIT 1").fetchone()
                perm = perm[0] if perm else None
            con.close()
    except Exception:
        pass

    high = [f for f in findings if f["risk"] == "HIGH"]
    result = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "credential_paths": findings,
        "sandbox_extra_allow_write": [display(x) for x in allow],
        "risky_allow_entries": risky_allow,
        "automation_permission_mode": perm,
        "high_risk_reachable_count": len(high),
        "remediation_playbook": [
            "1. 把私钥从 ~/.ssh 移到需二次授权的加密卷/密钥管理器，工作区只放公钥与配置别名。",
            "2. 用短期凭据替代常驻文件：CI 用 OIDC/短期 token；本机用系统钥匙串，Agent 需要时才手动授权。",
            "3. 在沙箱配置里显式拒绝读取凭据路径，并把 extraAllowWrite 中的敏感路径移除。",
            "4. 自动化任务若必须 fullAccess，确认其提示词已写死边界，且工作区内不存放任何可外传的凭据。",
            "5. 每月重跑本脚本；一旦 high_risk_reachable_count 上升，先查是不是新装的工具引入了凭据副本。",
        ],
        "verdict": "REVIEW" if (high or risky_allow) else "PASS",
        "note": "本脚本只报告可达性与元数据，不读取任何密钥内容，也不会自动迁移文件。",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print("[credential] written:", OUT)
    print("[credential] high-risk reachable:", len(high), "verdict:", result["verdict"])


if __name__ == "__main__":
    main()
