# SENTINEL Final Audit Report: vulnerable_project

- Overall Risk: **high**
- Total Components: 6
- Total Static Findings: 5
- Confirmed Findings: 4
- ASan Confirmed Findings: 4

## Component Risks
### libpng
- Version: 1.6.39
- Risk: unknown

### zlib
- Version: 1.2.13
- Risk: unknown

### curl
- Version: unknown
- Risk: high
- OSV-2025-657: Heap-use-after-free in ftp_pp_statemachine
- OSV-2022-1065: Stack-buffer-overflow in Curl_output_aws_sigv4
- OSV-2022-1046: Stack-buffer-overflow in Curl_output_aws_sigv4
- OSV-2022-450: Heap-buffer-overflow in Curl_headers_push
- OSV-2022-141: Heap-use-after-free in nghttp2_hd_deflate_hd_bufs

### sqlite
- Version: 3.45.0
- Risk: unknown

### libxml2
- Version: unknown
- Risk: high
- OSV-2026-565: Heap-buffer-overflow in xmlFAParsePosCharGroup
- OSV-2025-457: Heap-buffer-overflow in xmlParsePubidLiteral
- OSV-2025-74: Stack-buffer-overflow in xmlValidateElementContent
- OSV-2024-1209: Heap-use-after-free in xmlValidateOneElement
- OSV-2024-698: Heap-use-after-free in xmlCharEncCloseFunc

### openssl
- Version: 1.1.1t
- Risk: unknown

## Final Findings
### FINDING-0001 - Double Free
- File: `double_free_demo.c`
- Function: `double_free_case`
- Line Range: [8, 11]
- CWE: CWE-415
- Static Status: suspected
- Dynamic Status: **confirmed**
- Evidence Level: strong
- Dynamic Evidence Sources: ASAN, eBPF
- ASan Bug Type: `double-free`
- ASan Consistency: `matched_expected_cwe`
- ASan Log: `/mnt/vmshare/sentinel/harness_packages/HARNESS-0001/asan_double_free.log`
  - AddressSanitizer reported: double-free
  - Expected CWE from static audit: CWE-415
  - Target source location: ../../samples/vulnerable_project/double_free_demo.c:12
  - Target source location: ../../samples/vulnerable_project/double_free_demo.c:9
  - Target source location: ../../samples/vulnerable_project/double_free_demo.c:4
- Trigger Condition: Execution reaches free(buf) twice without reset or reallocation.
- Fix Suggestion: Set buf to NULL after free and avoid duplicate ownership.
- Final Conclusion: This suspected vulnerability is dynamically confirmed by ASAN, eBPF. Evidence level: strong.

### FINDING-0002 - Format String Vulnerability
- File: `format_string_demo.c`
- Function: `format_string_case`
- Line Range: [7, 7]
- CWE: CWE-134
- Static Status: suspected
- Dynamic Status: **untriggered**
- Evidence Level: weak
- Dynamic Evidence Sources: none
- Trigger Condition: Attacker-controlled input may be interpreted as a format string, enabling memory disclosure or arbitrary writes via %x/%s/%n tokens.
- Fix Suggestion: Use a constant format string such as printf("%s", input), fprintf(stream, "%s", input), or snprintf(buf, size, "%s", input).
- Final Conclusion: This suspected vulnerability was not triggered in the current dynamic validation run.

### FINDING-0003 - Heap Buffer Overflow
- File: `heap_overflow_demo.c`
- Function: `heap_overflow_case`
- Line Range: [9, 9]
- CWE: CWE-122
- Static Status: suspected
- Dynamic Status: **confirmed**
- Evidence Level: strong
- Dynamic Evidence Sources: ASAN, AFL++, eBPF
- ASan Bug Type: `heap-buffer-overflow`
- ASan Consistency: `matched_expected_cwe`
- ASan Log: `/mnt/vmshare/sentinel/harness_packages/HARNESS-0002/asan_heap.log`
  - AddressSanitizer reported: heap-buffer-overflow
  - Expected CWE from static audit: CWE-122
  - Memory access: WRITE of size 257
  - Target source location: /home/aut/桌面/sentinel/harness_packages/HARNESS-0002/../../samples/vulnerable_project/heap_overflow_demo.c:10
  - Target source location: /home/aut/桌面/sentinel/harness_packages/HARNESS-0002/../../samples/vulnerable_project/heap_overflow_demo.c:5
- Trigger Condition: Oversized or attacker-controlled input may reach a copy operation without sufficient length validation.
- Fix Suggestion: Validate length before copying and use bounded APIs with explicit destination size.
- Final Conclusion: This suspected vulnerability is dynamically confirmed by ASAN, AFL++, eBPF. Evidence level: strong.

### FINDING-0004 - Stack Buffer Overflow
- File: `stack_overflow_demo.c`
- Function: `stack_overflow_case`
- Line Range: [4, 4]
- CWE: CWE-121
- Static Status: suspected
- Dynamic Status: **confirmed**
- Evidence Level: strong
- Dynamic Evidence Sources: ASAN, AFL++
- ASan Bug Type: `stack-buffer-overflow`
- ASan Consistency: `matched_expected_cwe`
- ASan Log: `/mnt/vmshare/sentinel/harness_packages/HARNESS-0003/asan_stack.log`
  - AddressSanitizer reported: stack-buffer-overflow
  - Expected CWE from static audit: CWE-121
  - Memory access: WRITE of size 257
  - Target source location: /home/aut/桌面/sentinel/harness_packages/HARNESS-0003/../../samples/vulnerable_project/stack_overflow_demo.c:5
  - Target source location: /home/aut/桌面/sentinel/harness_packages/HARNESS-0003/../../samples/vulnerable_project/stack_overflow_demo.c:3
- Trigger Condition: Oversized or attacker-controlled input may reach a copy operation without sufficient length validation.
- Fix Suggestion: Validate length before copying and use bounded APIs with explicit destination size.
- Final Conclusion: This suspected vulnerability is dynamically confirmed by ASAN, AFL++. Evidence level: strong.

### FINDING-0005 - Use After Free
- File: `uaf_demo.c`
- Function: `uaf_case`
- Line Range: [10, 13]
- CWE: CWE-416
- Static Status: suspected
- Dynamic Status: **confirmed**
- Evidence Level: strong
- Dynamic Evidence Sources: ASAN, AFL++, eBPF
- ASan Bug Type: `heap-use-after-free`
- ASan Consistency: `matched_expected_cwe`
- ASan Log: `/mnt/vmshare/sentinel/harness_packages/HARNESS-0004/asan_uaf.log`
  - AddressSanitizer reported: heap-use-after-free
  - Expected CWE from static audit: CWE-416
  - Memory access: READ of size 4
  - Target source location: ../../samples/vulnerable_project/uaf_demo.c:14
  - Target source location: ../../samples/vulnerable_project/uaf_demo.c:11
  - Target source location: ../../samples/vulnerable_project/uaf_demo.c:5
- Trigger Condition: Pointer 'p' is dereferenced or accessed after free.
- Fix Suggestion: Do not access p after free; set it to NULL and guard future uses.
- Final Conclusion: This suspected vulnerability is dynamically confirmed by ASAN, AFL++, eBPF. Evidence level: strong.
