# Part 6：3 分钟演示讲稿

各位老师好，下面我演示我们系统的核心闭环。

首先，系统输入是一个 C/C++ 工程，里面既包含第三方依赖，也包含典型的内存安全漏洞样例。运行主程序后，Agent A 会从 include、CMakeLists.txt、Makefile、vcpkg.json 和 conanfile.txt 中识别第三方组件，并查询 OSV / NVD 漏洞信息。当前系统共识别出 6 个第三方组件。

接着，Agent B 会对源码进行函数级代码切片，并提取风险关键词、调用关系和上下文信息。系统不会直接把整个项目源码输入大模型，而是只把包含 malloc、free、strcpy 等高风险 API 的代码切片送入 Agent C，这样可以降低 token 消耗并减少无关上下文干扰。

然后，Agent C 调用大模型进行语义漏洞审计，重点检测 Use After Free、Double Free、Heap Buffer Overflow 和 Stack Buffer Overflow 四类漏洞。为了避免大模型输出不稳定，系统加入了 JSON 格式约束、置信度校准和规则 baseline 一致性校验。当前 4 个漏洞 finding 均由 LLM 输出，并且与规则 baseline 一致。

之后，Agent D 根据 CWE 类型自动生成 Harness 验证包。对于 Double Free 和 Use After Free，系统生成 flag 触发型 Harness；对于 Heap Buffer Overflow 和 Stack Buffer Overflow，系统生成超长字符串输入型 Harness。每个 Harness 包都包含 afl_harness.c、libfuzzer_harness.c、Makefile、seed 和 harness_config.json。

最后，系统使用 AddressSanitizer 对 Harness 进行真实动态验证。当前 4 个漏洞均被 ASan 成功确认，分别对应 double-free、heap-buffer-overflow、stack-buffer-overflow 和 heap-use-after-free。ASan 日志被解析成结构化 JSON 后接入 Agent E，最终报告中 4 个漏洞全部被标记为 confirmed。

因此，本系统完成了从供应链依赖识别、LLM 静态审计、Harness 自动生成，到 ASan 动态验证和最终报告输出的完整闭环。
