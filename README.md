# agent-security-baseline

> 把 ZCode 静默上传事件与 FreeBuf Agentjacking L1–L5 的教训，落成可执行、可复核、可开源的 AI Agent 本机安全基线。

**一句话**：只审计、不修复、不碰密钥。六个只读模块把"第三方工具清单 / 出站 HTTP 审计 / 涉密离线隔离 / 团队仓库 remote / 凭据卫生 / 组合告警"变成一条命令可跑的证据链。

## 为什么需要它

AI 编码助手的威胁模型和传统软件不同：**授权不等于安全**——每个操作都被授权了，但授权的对象是一段可能被外部内容操纵的推理过程。ZCode 事件（313MB 加密包上传失败 564 次，内含 `.git` 历史）说明风险不只在"传没传成功"，而在" agent 具备静默外传的能力"。

真正能消除能力的只有两件事：**网络层出站限制** + **凭据物理隔离**。本项目负责第三件：把前两件是否到位、以及有没有可疑行为，变成可复核的证据。

## 特性

- **只读**：不修改被审计的工作区、仓库、系统配置。
- **不碰密钥**：只取路径、文件名、大小、配置位；绝不打开私钥 / token / 凭证文件的内容。
- **输出脱敏**：home 目录折叠为 `~`；报告只给路径与 host，不贴命令行原文和值。
- **可配置**：允许域、敏感路径模式、扫描根、关联窗口全部外置到 `config.json`。
- **可 CI 化**：每个模块独立退出码，`verdict` 可直接接告警通道。

## 快速开始

```bash
git clone <your-repo-url> agent-security-baseline
cd agent-security-baseline
cp config.example.json config.json      # 按需修改，不会入库
python run_audit.py                     # 一条命令跑完六个模块
```

单独跑某个模块 / 指定扫描根：

```bash
python modules/remote_scan.py /path/to/repos /another/root
python modules/combo_alert.py
```

无第三方依赖，Python 3.8+ 标准库即可。

## 六个模块

| 模块 | 层 | 职责 | 输出 |
|---|---|---|---|
| `inventory.py` | L2 | 盘点 MCP / skills / 插件 / IDE 扩展 / CLI，生成第三方工具清单 | `data/inventory.json` |
| `egress_audit.py` | L4 | 核对出网拒绝配置位，从会话记录抽取真实外联 host 与白名单比对 | `data/egress_audit.json` |
| `secret_isolation.py` | L3 | 检查敏感路径是否落在 agent 可达范围、沙箱写白名单是否误放行 | `data/secret_isolation.json` |
| `remote_scan.py` | — | 遍历团队仓库 `git remote -v`，找陌生 remote（ZCode 自查动作） | `data/remote_scan.json` |
| `credential_hygiene.py` | L3 | 凭据可达性评级 + 移出清单（只给步骤，不自动迁移） | `data/credential_hygiene.json` |
| `combo_alert.py` | L5 | 检测"读敏感路径 → 外联"的组合行为，带时间窗口与白名单 | `data/combo_alert.json` |

总控汇总到 `data/summary.json`。

## 配置

复制 `config.example.json` 为 `config.json`（已被 `.gitignore` 排除）：

- `allowed_egress_hosts`：允许外联的 host。建议只列包源、模型 API、代码托管，不留通配。
- `trusted_remote_host_hints`：可信 git remote 主机关键字。
- `scan_roots` / `sessions_dir` / `workbuddy_dir`：按你的实际路径改，支持 `~`。
- `credential_paths` / `sensitive_path_patterns`：按你实际使用的凭据文件名补充。
- `combo_window_seconds`：组合告警关联窗口，默认 300 秒。

## 判读

| verdict | 含义 |
|---|---|
| `PASS` | 该维度未发现异常 |
| `REVIEW` | 需人工确认（白名单外的 host、可疑 remote、高可达凭据） |
| `ALERT` | 出现组合告警，需查原始会话记录 |
| `ERROR` | 模块执行失败，看 `stderr` |

**告警不等于定性**：读包管理器配置后访问官方源是典型误报。收到 `ALERT` 先查 `sessions/*.jsonl` 对应会话，再决定是否升级。发现缺口先看 `L3_L5_操作清单.md`，所有修复动作由你手动执行。

## L1–L5 覆盖

| 层 | 本项目的控制点 | 仍需你手动落地 |
|---|---|---|
| L1 数据入口 | 边界声明模板 | 把 README / issue / 代码注释标记为不可信输入 |
| L2 工具网关 | `inventory.py` 工具清单 | MCP / skills 准入审批 |
| L3 运行时 | `secret_isolation.py` + `credential_hygiene.py` | 凭据物理移出、低权身份 |
| L4 执行控制 | `egress_audit.py` 证据核对 | 出站防火墙白名单、高危命令审批 |
| L5 身份审计 | `combo_alert.py` 组合告警 | Agent 独立身份、告警通道 |

> 审计是兜底，不是替代。前两层的能力消除做不到位，检测再全也只能事后发现。

## 目录结构

```
.
├── run_audit.py                 # 总控
├── config.example.json          # 配置模板（复制为 config.json）
├── modules/                     # 六个只读审计模块
├── data/                        # 运行产出（.gitignore 排除，含本机路径）
├── L1-L5_缺口台账.md
├── L3_L5_操作清单.md
├── 第三方工具清单模板.md
├── CONTRIBUTING.md
└── LICENSE                      # MIT
```

## 参考

- ZCode 事件：澎湃新闻 / 中国新闻周刊 / 每日经济新闻 2026-09-21 报道
- FreeBuf《一个伪造的 Bug 报告，就能接管你的 AI 编码助手——Agentjacking 实战复现》
- AgentOffense《AI Coding Agent Security: What to Lock Down First》
- 《智能体安全互联自律公约》2026-11-12

## 许可

MIT — 见 [LICENSE](LICENSE)。
