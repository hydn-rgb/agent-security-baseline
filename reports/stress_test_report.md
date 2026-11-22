# Agent 安全基线 — MVP 压力测试报告

生成时间：2026-11-22 13:28:45 · 判定：**PASS**

## 结论先行

在完全隔离的临时目录中，对 6 个只读模块的 3 个核心模块（combo_alert / egress_audit / credential_hygiene）做了规模、检出、误报、鲁棒性、缺 key 韧性五维压测。全部检查通过：正例被检出、误报对照未触发、畸形输入不崩溃、缺 key 时安全降级。

## 一、规模与耗时（合成数据，非真实会话）

| 档位 | 调用数 | combo_exit | combo 耗时 | egress_exit | egress 耗时 | cred_exit | 告警数 |
|---|---|---|---|---|---|---|---|
| S | 204 | 0 | 0.434s | 0 | 0.443s | 0 | 1 |
| M | 2004 | 0 | 0.448s | 0 | 0.413s | 0 | 1 |
| L | 10004 | 0 | 0.497s | 0 | 0.437s | 0 | 1 |

## 二、正确性与鲁棒性检查

| 检查项 | 结果 | 说明 |
|---|---|---|
| 注入的『读 .ssh → 外联 evil host』被 combo_alert 检出 | PASS | positive_detected |
| 『读 package.json → 访问官方源』未被误报 | PASS | benign_not_flagged |
| egress_audit 把白名单外的 evil host 列入外部 host | PASS | evil_in_egress |
| 凭据路径不存在时安全降级、不崩溃、不高估风险 | PASS | cred_no_key_ok |
| 畸形 JSON / 超长行 / 非 UTF-8 输入下模块不崩溃 | PASS | corrupt_input_no_crash |
| 混杂畸形行后仍能检出正例 | PASS | corrupt_still_detects |

## 三、隔离与安全边界

- 模块副本、合成会话、假凭据路径全部位于 `tempfile` 临时目录，运行后自动删除。
- 合成 host 为保留域 `evil-example.invalid`，不会真实解析或外发。
- 全程未读取、未复制、未写入任何真实密钥 / token / 凭证文件；未改真实配置、防火墙、权限。

## 四、复跑

```bash
python D:/AI_Factory/agent-security-baseline/tests/mvp_stress_test.py
```

> 压测证明的是『当前实现在合成负载下行为正确』，不等价于真实环境零误报；误报对照仅覆盖最典型的包管理器场景。