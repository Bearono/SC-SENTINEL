# 问题分析与修复方案

## 问题1: Stream输出与阶段进度不协调

### 根因
`MonitorView.vue` 同时展示两种日志：
1. **真实日志**（`store.progressLogs`）- 来自WebSocket
2. **模拟日志**（`simLogs`）- 前端按固定时间间隔注入

当任务已经运行一段时间后才打开页面时，模拟日志会立刻"预加载"历史行（代码145-150行），导致：
- 模拟日志显示"AFL++运行中"
- 但真实进度已经到"结果保存"阶段

### 解决方案
禁用模拟日志，完全依赖后端真实日志流。

**修改文件**: `sentinel_frontend/src/views/MonitorView.vue`

删除或注释掉模拟日志逻辑（101-159行），仅保留真实日志：

```javascript
const logLines = computed(() => {
  const out: { time: string; text: string; cls: string }[] = []
  for (const log of store.progressLogs) {
    const t = log.timestamp ? new Date(log.timestamp).toLocaleTimeString('en-GB') : ''
    if (log.message) out.push({ time: t, text: log.message, cls: lineClass(log.stage, log.message) })
    if (log.log_stream) {
      for (const raw of log.log_stream.split('\n')) {
        if (raw.trim()) out.push({ time: t, text: raw, cls: lineClass(log.stage, raw) })
      }
    }
  }
  // 删除: for (const s of simLogs.value) out.push(s)
  return out
})
```

## 问题2: Modbus stack overflow误判为heap overflow

### 根因
静态分析看到 `write_u16be(response + 9 + i * 2, val)` 这种指针运算，LLM可能基于以下推理：
- `response + offset` 形式类似堆指针操作
- 没有明显的栈数组边界检查
- CWE-122（heap overflow）和CWE-121（stack overflow）的pattern重叠

### 根本问题
Agent C的静态审计依赖LLM理解上下文，但：
1. **上下文窗口有限** - 只传递了函数体，没有变量声明
2. **CWE分类粒度粗** - 规则引擎只能判断"buffer overflow"，细分stack/heap需要变量类型信息

### 解决方案

#### 方案A: 增强上下文传递（推荐）

修改 `agent_c_static_audit.py` 的 LLM prompt，显式传递变量声明信息：

```python
def llm_audit_slice(llm_client, agent_a_result, slc, function_lines, rule_findings):
    # 提取局部变量声明
    local_vars = extract_local_variables(function_lines)
    
    prompt = f"""Analyze this C function for memory vulnerabilities.

**Variable Declarations:**
{local_vars}

**Function Code:**
{function_lines}

**CRITICAL: Distinguish stack vs heap:**
- If buffer is declared as `type array[SIZE]` → Stack overflow (CWE-121)
- If buffer is from malloc/calloc/new → Heap overflow (CWE-122)

Return JSON with accurate CWE classification."""
```

添加辅助函数：
```python
def extract_local_variables(code):
    """Extract local variable declarations with their types."""
    vars = []
    for line in code.split('\n'):
        # Match: type name[size]; or type *name = malloc(...)
        if match := re.search(r'^\s*((?:uint8_t|char|int|unsigned)\s+\w+\[[^\]]+\])', line):
            vars.append(match.group(1) + ' → STACK BUFFER')
        elif match := re.search(r'^\s*(\w+\s+\*\w+\s*=\s*(?:malloc|calloc))', line):
            vars.append(match.group(1) + ' → HEAP BUFFER')
    return '\n'.join(vars) if vars else 'No explicit buffer declarations found'
```

#### 方案B: 规则后处理

在保存结果时，根据栈数组pattern修正CWE：

```python
# sentinel_backend/app/worker/llm_task.py

def correct_cwe_classification(vuln, code_context):
    """Post-process CWE based on code patterns."""
    if vuln.get('cwe_id') == 'CWE-122':  # heap overflow
        # Check if actually stack buffer
        if re.search(r'(uint8_t|char|int)\s+\w+\[', code_context):
            vuln['cwe_id'] = 'CWE-121'
            vuln['vulnerability_type'] = 'Stack-based Buffer Overflow'
    return vuln
```

## 问题3: Double free没有crash + COMPONENT RISKS为0

### 问题3.1: Double free未触发crash

**原因**: 
1. **seed不匹配** - 默认的double free seed（`\x01`, `trigger=1`）不符合tree程序的输入格式
2. **触发路径复杂** - double free需要特定的函数调用序列

**解决方案**: 增强LLM seed生成的协议理解能力

修改 `sentinel_agent/agents/agent_d_harness.py` 的prompt：

```python
def generate_seeds_with_llm(finding, strategy, project_root=None):
    # ... 前面代码不变 ...
    
    # 分析main函数获取输入格式
    input_format_hint = ""
    if project_root and finding.get("file"):
        main_file = find_main_file(project_root)
        if main_file:
            main_code = main_file.read_text(encoding="utf-8", errors="replace")[:1000]
            input_format_hint = f"\n**Main function input parsing:**\n```c\n{main_code}\n```"
    
    prompt = f"""Generate AFL++ seeds for {finding.get('cwe_id')}.

{input_format_hint}

**For CWE-415 (Double Free):**
The program must execute a specific call sequence to trigger double-free.
Analyze the main() parsing logic and generate inputs that:
1. Trigger the vulnerable function multiple times
2. Pass through error recovery paths
3. Reuse the same node/pointer

Example for tree-based structures:
- Input "add A; add B; replace A A; free A" triggers double-free via replace
- Input "add X; add Y to X; add Y to Z; free X; free Z" triggers shared child

Generate 3-5 seeds in format expected by this program."""
```

添加辅助函数：
```python
def find_main_file(project_root):
    """Find main.c or file containing main() function."""
    candidates = list(Path(project_root).rglob("main.c"))
    if candidates:
        return candidates[0]
    for c_file in Path(project_root).rglob("*.c"):
        if "int main(" in c_file.read_text(encoding="utf-8", errors="replace"):
            return c_file
    return None
```

### 问题3.2: COMPONENT RISKS为0

**原因**: 
Agent A的CVE检测依赖：
1. **依赖声明文件** - CMakeLists.txt, conanfile.txt等
2. **#include分析** - 推断使用的第三方库

如果项目是自包含的（无外部依赖），自然COMPONENT RISKS=0。

**这是正常的！** 04_tree_doublefree只有两个C文件，没有外部依赖。

**可选优化**: 显示"No external dependencies detected"而不是空白：

```javascript
// sentinel_frontend/src/views/ReportView.vue

<div v-if="componentRisks.length === 0" class="empty-state">
  <p>ℹ️ No external dependencies detected</p>
  <p class="text-sm">This project appears to be self-contained with no third-party libraries.</p>
</div>
```

## 修复优先级

### P0 - 立即修复
1. ✅ 问题1: 删除模拟日志逻辑
2. ✅ 问题3.2: 添加"No dependencies"提示

### P1 - 重要但不紧急
3. 问题2: 增强上下文传递（方案A）

### P2 - 优化项
4. 问题3.1: 增强seed生成（需要测试迭代）

## 快速修复脚本

创建 `quick_fix.sh`:
```bash
#!/bin/bash
echo "应用快速修复..."

# 修复1: 禁用模拟日志
echo "1. 禁用模拟日志..."
# 手动编辑 MonitorView.vue 或用sed（Windows环境建议手动）

# 修复2: 重新构建前端
echo "2. 重新构建前端..."
docker compose build frontend
docker compose up -d frontend

echo "✓ 修复完成"
```

## 验证步骤

测试03_modbus:
```bash
# 1. 上传03_modbus
# 2. 检查漏洞类型是否为CWE-121（stack overflow）
# 3. 确认有crash
```

测试04_tree:
```bash
# 1. 上传04_tree
# 2. 确认COMPONENT RISKS显示"No dependencies"
# 3. 查看生成的seed是否包含命令序列（如"add X; replace X X"）
```
