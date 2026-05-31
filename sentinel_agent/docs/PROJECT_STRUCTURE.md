# SENTINEL 项目目录说明

以下为当前版本的核心目录结构说明。

```text
sentinel/
├── agents/
│   ├── agent_a_dependency.py
│   ├── agent_b_slicer.py
│   ├── agent_c_static_audit.py
│   ├── agent_d_harness.py
│   └── agent_e_final_report.py
│
├── core/
│   ├── file_scanner.py
│   ├── json_utils.py
│   ├── llm_client.py
│   ├── env_loader.py
│   └── risk_level.py
│
├── cve/
│   ├── dependency_parser.py
│   ├── osv_client.py
│   ├── nvd_client.py
│   ├── risk_inference.py
│   └── cve_cache.json
│
├── prompts/
│   └── static_audit_prompt.txt
│
├── samples/
│   └── vulnerable_project/
│       ├── double_free_demo.c
│       ├── heap_overflow_demo.c
│       ├── stack_overflow_demo.c
│       ├── uaf_demo.c
│       ├── openssl_component_demo.c
│       ├── multi_component_demo.c
│       ├── CMakeLists.txt
│       ├── Makefile
│       ├── vcpkg.json
│       └── conanfile.txt
│
├── harness_packages/
│   ├── HARNESS-0001/
│   ├── HARNESS-0002/
│   ├── HARNESS-0003/
│   └── HARNESS-0004/
│
├── validation/
│   ├── afl_result_example.json
│   ├── ebpf_log_example.json
│   └── asan_validation_results.json
│
├── outputs/
│   ├── final_report.md
│   ├── final_report.json
│   ├── agent_a_components.json
│   ├── agent_b_slices.json
│   ├── agent_c_findings.json
│   └── agent_d_harness_packages.json
│
├── tools/
│   ├── parse_asan_logs.py
│   ├── test_llm_connection.py
│   └── collect_demo_artifacts.py
│
├── scripts/
│   ├── 01_run_pipeline.sh
│   ├── 02_parse_asan_and_update_report.sh
│   └── 03_collect_demo_artifacts.sh
│
├── docs/
│   ├── part6_demo_delivery_guide.md
│   ├── part6_demo_script.md
│   ├── part6_delivery_checklist.md
│   └── ...
│
├── demo_artifacts/
│   └── sentinel_demo_artifacts_时间戳.zip
│
├── main.py
├── requirements.txt
├── README.md
└── .env
```

## 1. agents/

`agents/` 是系统核心的五 Agent 实现目录。

| 文件 | 作用 |
|---|---|
| `agent_a_dependency.py` | 供应链依赖风险识别，解析 include / CMake / Makefile / vcpkg / conan，并查询 OSV / NVD |
| `agent_b_slicer.py` | C/C++ 函数级代码切片，上下文裁剪，风险关键词识别 |
| `agent_c_static_audit.py` | LLM 漏洞审计，规则 fallback，质量控制和一致性校验 |
| `agent_d_harness.py` | 根据 CWE 类型自动生成 Harness、seed、Makefile 和验证包 |
| `agent_e_final_report.py` | 汇总静态发现、ASan 动态证据和组件风险，生成最终报告 |

## 2. core/

`core/` 是基础工具层。

| 文件 | 作用 |
|---|---|
| `file_scanner.py` | 扫描 C/C++ 源码和项目元数据文件 |
| `json_utils.py` | JSON 读写工具 |
| `llm_client.py` | OpenAI-compatible LLM API 客户端 |
| `env_loader.py` | 加载 `.env` 配置 |
| `risk_level.py` | 风险等级比较工具 |

## 3. cve/

`cve/` 负责第三方依赖解析和漏洞库查询。

| 文件 | 作用 |
|---|---|
| `dependency_parser.py` | 从 include、CMake、Makefile、vcpkg、conan 中识别组件 |
| `osv_client.py` | 查询 OSV API |
| `nvd_client.py` | 查询 NVD CVE API |
| `risk_inference.py` | 对缺少 CVSS 的漏洞记录进行文本风险推断 |
| `cve_cache.json` | 本地缓存 OSV / NVD 查询结果 |

## 4. samples/vulnerable_project/

样例 C/C++ 项目，用于演示系统能力。

| 文件 | 漏洞或作用 |
|---|---|
| `double_free_demo.c` | CWE-415 Double Free |
| `heap_overflow_demo.c` | CWE-122 Heap Buffer Overflow |
| `stack_overflow_demo.c` | CWE-121 Stack Buffer Overflow |
| `uaf_demo.c` | CWE-416 Use After Free |
| `openssl_component_demo.c` | OpenSSL include 依赖识别 |
| `multi_component_demo.c` | libpng / zlib / curl / sqlite / libxml2 include 依赖识别 |
| `CMakeLists.txt` | CMake 依赖识别 |
| `Makefile` | Makefile 链接依赖识别 |
| `vcpkg.json` | vcpkg 依赖识别 |
| `conanfile.txt` | Conan 依赖识别 |

## 5. harness_packages/

Agent D 生成的动态验证包目录。

每个 Harness 包包含：

```text
afl_harness.c
libfuzzer_harness.c
Makefile
README.md
harness_config.json
seeds/
findings/
*.log
```

当前对应关系：

| 目录 | 对应漏洞 |
|---|---|
| `HARNESS-0001` | Double Free |
| `HARNESS-0002` | Heap Buffer Overflow |
| `HARNESS-0003` | Stack Buffer Overflow |
| `HARNESS-0004` | Use After Free |

## 6. validation/

动态验证输入与结果目录。

| 文件 | 作用 |
|---|---|
| `afl_result_example.json` | AFL++ mock 结果，兼容旧流程 |
| `ebpf_log_example.json` | eBPF mock 日志，兼容旧流程 |
| `asan_validation_results.json` | 真实 ASan 日志解析结果，当前 Agent E 的主要动态证据来源 |

## 7. outputs/

系统运行后生成的核心输出。

| 文件 | 作用 |
|---|---|
| `final_report.md` | 最终 Markdown 报告 |
| `final_report.json` | 最终结构化 JSON 报告 |
| `agent_a_components.json` | Agent A 组件风险识别结果 |
| `agent_b_slices.json` | Agent B 代码切片结果 |
| `agent_c_findings.json` | Agent C LLM 审计结果 |
| `agent_d_harness_packages.json` | Agent D Harness 生成结果 |

## 8. scripts/

演示脚本目录。

| 文件 | 作用 |
|---|---|
| `01_run_pipeline.sh` | 一键运行五 Agent 主流程 |
| `02_parse_asan_and_update_report.sh` | 一键解析 ASan 日志并更新最终报告 |
| `03_collect_demo_artifacts.sh` | 一键收集演示材料并打包 |

## 9. tools/

工具脚本目录。

| 文件 | 作用 |
|---|---|
| `parse_asan_logs.py` | 解析 ASan 日志，生成 `validation/asan_validation_results.json` |
| `collect_demo_artifacts.py` | 收集核心输出、ASan 日志和文档，生成演示材料包 |
| `test_llm_connection.py` | 测试 LLM API 配置是否可用 |

## 10. demo_artifacts/

演示材料输出目录。

运行：

```bash
bash scripts/03_collect_demo_artifacts.sh /mnt/vmshare/sentinel
```

后会生成：

```text
demo_artifacts/sentinel_demo_artifacts_时间戳/
demo_artifacts/sentinel_demo_artifacts_时间戳.zip
```

该 zip 可用于提交、答辩展示或同步给队友。
