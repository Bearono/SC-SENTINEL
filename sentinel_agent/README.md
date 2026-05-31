# SENTINEL：面向 C/C++ 开源供应链的 LLM 协同漏洞审计与动态验证系统

## 1. 项目简介

SENTINEL 是一个面向 C/C++ 开源供应链场景的 Multi-Agent 漏洞审计与安全管理原型系统。系统围绕“依赖识别、代码切片、大模型审计、Harness 生成、动态验证、最终研判”构建自动化分析流程，目标是解决 C/C++ 项目中第三方依赖风险难识别、源码审计成本高、大模型直接审计长代码不稳定、静态审计缺少运行时证据等问题。

当前版本已经完成从静态审计到动态验证的完整闭环：

```text
C/C++ 项目输入
  ↓
Agent A：供应链依赖风险识别
  ↓
Agent B：代码切片与上下文裁剪
  ↓
Agent C：LLM 漏洞语义审计 + 质量控制
  ↓
Agent D：Harness 自动生成
  ↓
AddressSanitizer：真实动态验证
  ↓
Agent E：最终研判与报告生成
```

## 2. 当前验证结果

当前样例项目的最终运行结果如下：

| 指标 | 结果 |
|---|---:|
| 第三方组件识别数量 | 6 |
| 静态漏洞发现数量 | 4 |
| Harness 生成数量 | 4 |
| ASan 动态确认数量 | 4 |
| 最终 confirmed findings | 4 |

已动态确认的漏洞包括：

| Finding | CWE | 漏洞类型 | ASan 验证结果 | 最终状态 |
|---|---|---|---|---|
| FINDING-0001 | CWE-415 | Double Free | double-free | confirmed |
| FINDING-0002 | CWE-122 | Heap Buffer Overflow | heap-buffer-overflow | confirmed |
| FINDING-0003 | CWE-121 | Stack Buffer Overflow | stack-buffer-overflow | confirmed |
| FINDING-0004 | CWE-416 | Use After Free | heap-use-after-free | confirmed |

## 3. 系统环境

推荐环境：

```text
Ubuntu / Linux 虚拟机 / WSL2
Python 3.9+
clang
make
AddressSanitizer
```

基础依赖安装：

```bash
sudo apt update
sudo apt install -y build-essential clang make unzip zip
```

Python 依赖安装：

```bash
pip install -r requirements.txt
```

如果使用 LLM API，请在项目根目录配置 `.env`：

```text
LLM_API_KEY=你的API_KEY
LLM_BASE_URL=https://你的服务商地址/v1
LLM_MODEL=你的模型名称
LLM_TIMEOUT=60
LLM_TEMPERATURE=0
LLM_DISABLE_PROXY=1
LLM_VERIFY_SSL=1
```

如果不配置 LLM，系统仍可使用规则 fallback 运行，但不属于完整 LLM 审计演示模式。

## 4. 快速运行

假设项目位于：

```bash
/mnt/vmshare/sentinel
```

进入项目目录：

```bash
cd /mnt/vmshare/sentinel
```

### 4.1 运行完整五 Agent 流程

```bash
bash scripts/01_run_pipeline.sh /mnt/vmshare/sentinel
```

预期输出应包含：

```text
Components: 6
Static Findings: 4
Harness Packages: 4
Confirmed Findings: 4
ASan Confirmed Findings: 4
```

### 4.2 解析 ASan 日志并更新最终报告

```bash
bash scripts/02_parse_asan_and_update_report.sh /mnt/vmshare/sentinel
```

预期输出应包含：

```text
Total logs: 4
Confirmed findings: 4
Failed or unconfirmed: 0
ASan Confirmed Findings: 4
```

### 4.3 收集演示材料

```bash
bash scripts/03_collect_demo_artifacts.sh /mnt/vmshare/sentinel
```

运行后会生成：

```text
demo_artifacts/sentinel_demo_artifacts_时间戳/
demo_artifacts/sentinel_demo_artifacts_时间戳.zip
```

该 zip 包可用于提交、答辩展示或同步给队友。

## 5. 手动运行主程序

也可以不使用脚本，直接运行：

```bash
python3 main.py --project ./samples/vulnerable_project
```

运行完成后，核心输出位于：

```text
outputs/final_report.md
outputs/final_report.json
outputs/agent_a_components.json
outputs/agent_b_slices.json
outputs/agent_c_findings.json
outputs/agent_d_harness_packages.json
```

## 6. ASan 动态验证

系统已经生成 4 个 Harness 包：

```text
harness_packages/HARNESS-0001
harness_packages/HARNESS-0002
harness_packages/HARNESS-0003
harness_packages/HARNESS-0004
```

每个 Harness 包包含：

```text
afl_harness.c
libfuzzer_harness.c
Makefile
README.md
harness_config.json
seeds/
findings/
```

手动运行某个 Harness 的方式如下：

```bash
cd /mnt/vmshare/sentinel/harness_packages/HARNESS-0001
make clean
make asan
ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:symbolize=1:detect_leaks=0 ./asan_target seeds/seed_001.bin 2>&1 | tee asan_double_free.log
```

对于缓冲区溢出类 Harness，推荐使用 clang 和更适合 ASan 的编译参数：

```bash
make clean
make asan CC=clang COMMON_FLAGS='-g -O0 -fsanitize=address -fno-omit-frame-pointer -fno-builtin -U_FORTIFY_SOURCE'
ASAN_OPTIONS=halt_on_error=1:abort_on_error=0:symbolize=1:detect_leaks=0 ./asan_target seeds/seed_001.bin 2>&1 | tee asan_heap.log
```

## 7. ASan 日志解析

确认以下日志存在：

```text
harness_packages/HARNESS-0001/asan_double_free.log
harness_packages/HARNESS-0002/asan_heap.log
harness_packages/HARNESS-0003/asan_stack.log
harness_packages/HARNESS-0004/asan_uaf.log
```

解析日志：

```bash
python3 tools/parse_asan_logs.py \
  --harness-root harness_packages \
  --output validation/asan_validation_results.json
```

成功后应看到：

```text
Total logs: 4
Confirmed findings: 4
Failed or unconfirmed: 0
```

## 8. 最终报告查看

查看 Markdown 报告：

```bash
cat outputs/final_report.md
```

查看 ASan 相关结论：

```bash
grep -n "ASan" outputs/final_report.md
```

预期包括：

```text
ASan Confirmed Findings: 4
ASan Bug Type: `double-free`
ASan Bug Type: `heap-buffer-overflow`
ASan Bug Type: `stack-buffer-overflow`
ASan Bug Type: `heap-use-after-free`
```

## 9. 项目亮点

1. 面向 C/C++ 开源供应链场景，既识别第三方组件风险，也审计项目源码漏洞。
2. 采用 Agent B 进行函数级代码切片，避免直接把完整项目源码输入大模型。
3. Agent C 引入 LLM 审计、规则 baseline、一致性校验和置信度质量控制。
4. Agent D 根据 CWE 类型自动生成 Harness 和 seed。
5. 通过 AddressSanitizer 对 LLM 静态发现进行真实动态验证。
6. Agent E 将静态审计结果和动态验证证据整合为最终 confirmed 报告。

## 10. 当前限制

当前系统仍是原型系统，存在以下限制：

1. Agent B 当前主要采用轻量级启发式切片，对复杂宏展开、模板、跨文件调用链支持有限。
2. Agent D 对样例项目可直接生成可运行 Harness，但真实大型项目可能需要适配构建系统、头文件路径和初始化逻辑。
3. 当前动态验证主要使用 ASan，AFL++ 和 eBPF 可作为后续增强方向。
4. LLM 审计结果虽然加入了质量控制，但真实项目仍建议配合人工复核。

## 11. 推荐演示顺序

答辩或演示时建议按照以下顺序展示：

```text
1. 运行 bash scripts/01_run_pipeline.sh
2. 展示 Agent A 识别 6 个组件
3. 展示 Agent C 中 audit_source=llm 和 rule_consistency=consistent
4. 展示 Agent D 生成 4 个 Harness 包
5. 展示 4 个 ASan 原始日志
6. 运行 bash scripts/02_parse_asan_and_update_report.sh
7. 展示 final_report.md 中 ASan Confirmed Findings: 4
8. 展示 demo_artifacts zip 作为最终交付包
```
