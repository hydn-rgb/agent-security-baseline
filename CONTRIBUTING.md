# 贡献指南

欢迎补充审计维度、改进误报过滤、分享不同平台的路径规则。

## 硬约束（不可协商）

1. **只读**：任何模块不得修改被审计对象（工作区、仓库、系统配置、凭据）。
2. **不碰密钥**：不得 `open()` / 复制 / 打印 / 上传任何私钥、token、凭证文件的内容。只允许取路径、文件名、大小、权限位等元数据。
3. **不自动修复**：发现缺口只出报告与操作清单；执行权永远在用户手里。
4. **输出脱敏**：报告里 home 目录折叠为 `~`；不贴完整命令行、完整 URL、token 值。

## 提交前自检

```bash
python run_audit.py          # 六个模块必须全部 exit=0
git status --short           # data/ 与 config.json 不得出现在待提交列表
grep -r "Users\\\\" modules/   # 不得出现硬编码的本机账户路径
```

## 新增模块约定

- 放在 `modules/`，独立可执行，输出 `data/<模块名>.json`。
- 用 `ROOT / "config.json"`（回退 `config.example.json`）读配置，不硬编码个人路径。
- 结果至少含 `generated_at` 与 `verdict`（`PASS` / `REVIEW` / `ALERT` / `ERROR`）。
- 在 `run_audit.py` 的 `MODULES` 列表登记，并同步更新 README 与 `L1-L5_缺口台账.md`。

## 误报处理

宁可漏报也不误伤正常开发流：提交误报修复时请附上"为什么这是正常行为"的说明与复现条件。
