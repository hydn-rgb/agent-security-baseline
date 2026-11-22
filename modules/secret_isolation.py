#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块 3：涉密项目离线隔离检查
检查敏感凭据路径是否存在、是否落在 agent 工作区可达范围内。
只读元数据：路径存在性、目录条目名称、文件大小 —— 从不打开凭据文件内容。
输出 data/secret_isolation.json。
"""
import json, os, pathlib, datetime

HOME = pathlib.Path(os.environ.get("USERPROFILE", ""))
WB = HOME / ".workbuddy"
ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "secret_isolation.json"

SECRET_PATHS = [
    HOME / ".ssh", HOME / ".aws", HOME / ".config" / "gcloud",
    WB / "keyblob", WB / "security", HOME / "AppData" / "Roaming" / "npmrc",
    HOME / ".gitconfig", HOME / ".netrc",
]


def main():
    findings = []
    for p in SECRET_PATHS:
        item = {"path": str(p), "exists": p.exists()}
        if p.exists():
            try:
                if p.is_dir():
                    names = [x.name for x in p.iterdir()]
                    item["type"] = "dir"
                    item["entry_count"] = len(names)
                    item["entries"] = names[:12]
                    # 标出疑似私钥（只看文件名）
                    item["key_files"] = [n for n in names
                                         if n.startswith("id_") and ".pub" not in n]
                else:
                    item["type"] = "file"
                    item["size"] = p.stat().st_size
            except Exception as e:
                item["error"] = type(e).__name__
        findings.append(item)

    # 沙箱写入白名单里是否含敏感路径
    try:
        settings = json.loads((WB / "settings.json").read_text(encoding="utf-8"))
        allow = settings.get("sandbox", {}).get("extraAllowWrite", [])
    except Exception:
        allow = []
    risky_allow = [x for x in allow if any(k in x.lower() for k in
                   (".ssh", ".aws", "keyblob", "credential", "token", "secret"))]

    result = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "secret_paths": findings,
        "sandbox_extra_allow_write": allow,
        "risky_allow_entries": risky_allow,
        "offline_isolation": {
            "workbuddy_network_deny_all": json.loads(
                (WB / "settings.json").read_text(encoding="utf-8")
            ).get("sandbox", {}).get("networkDenyAllMigrated"),
            "note": "离线隔离需要：涉密仓库放在 network deny 的工作区 + 独立低权身份；当前仅验证配置位。",
        },
        "verdict": "PASS" if not risky_allow else "REVIEW",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print("[isolation] written:", OUT)
    print("[isolation] risky allow entries:", len(risky_allow))


if __name__ == "__main__":
    main()
