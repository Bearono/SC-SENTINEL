# SENTINEL Final Audit Report: level1_testset

- Overall Risk: **high**
- Total Components: 0
- Total Slices: 47
- Total Hypotheses: 28
- Total Static Findings: 28
- Harness Packages: 28
- Confirmed Findings: 0
- ASan Confirmed Findings: 0

## Seven-Agent Trace

```text
Agent A -> Agent B -> Agent C -> Agent D -> Agent E -> Agent F -> Agent G
dependency -> slice -> hypothesis -> finding -> harness -> evidence -> decision
```

## Component Risks
No dependency risks were inferred.
## Final Findings
### FINDING-0001 - Use After Free
- File: `uaf_direct.c`
- Function: `run_note_machine`
- CWE: `CWE-416`
- Hypothesis: `HYP-0001`
- Slice: `SLICE-0043`
- Harness Package: `HARNESS-0001`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: AFL++, eBPF
- Trigger Condition: Pointer 'note' is accessed after free.
- Fix Suggestion: Do not access note after free; set it to NULL and guard future uses.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from AFL++, eBPF and needs manual review.

### FINDING-0002 - Heap Buffer Overflow
- File: `uaf_direct.c`
- Function: `run_note_machine`
- CWE: `CWE-122`
- Hypothesis: `HYP-0002`
- Slice: `SLICE-0043`
- Harness Package: `HARNESS-0002`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: AFL++, eBPF
- Trigger Condition: Dangerous copy-style operation may write beyond destination bounds.
- Fix Suggestion: Validate input length and use bounded APIs with explicit destination size.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from AFL++, eBPF and needs manual review.

### FINDING-0003 - Heap Buffer Overflow
- File: `heap_overflow_strcpy.c`
- Function: `create_and_edit`
- CWE: `CWE-122`
- Hypothesis: `HYP-0003`
- Slice: `SLICE-0027`
- Harness Package: `HARNESS-0003`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: AFL++, eBPF
- Trigger Condition: Dangerous copy-style operation may write beyond destination bounds.
- Fix Suggestion: Validate input length and use bounded APIs with explicit destination size.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from AFL++, eBPF and needs manual review.

### FINDING-0004 - Heap Buffer Overflow
- File: `heap_overflow_memcpy_len.c`
- Function: `edit_chunk`
- CWE: `CWE-122`
- Hypothesis: `HYP-0004`
- Slice: `SLICE-0023`
- Harness Package: `HARNESS-0004`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: AFL++, eBPF
- Trigger Condition: Dangerous copy-style operation may write beyond destination bounds.
- Fix Suggestion: Validate input length and use bounded APIs with explicit destination size.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from AFL++, eBPF and needs manual review.

### FINDING-0005 - Heap Buffer Overflow
- File: `heap_overflow_off_by_one.c`
- Function: `rename_chunk`
- CWE: `CWE-122`
- Hypothesis: `HYP-0005`
- Slice: `SLICE-0025`
- Harness Package: `HARNESS-0005`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: AFL++, eBPF
- Trigger Condition: Dangerous copy-style operation may write beyond destination bounds.
- Fix Suggestion: Validate input length and use bounded APIs with explicit destination size.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from AFL++, eBPF and needs manual review.

### FINDING-0006 - Heap Buffer Overflow
- File: `heap_overflow_integer_trunc.c`
- Function: `resize_then_write`
- CWE: `CWE-122`
- Hypothesis: `HYP-0006`
- Slice: `SLICE-0021`
- Harness Package: `HARNESS-0006`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: AFL++, eBPF
- Trigger Condition: Dangerous copy-style operation may write beyond destination bounds.
- Fix Suggestion: Validate input length and use bounded APIs with explicit destination size.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from AFL++, eBPF and needs manual review.

### FINDING-0007 - Double Free
- File: `double_free_alias.c`
- Function: `main`
- CWE: `CWE-415`
- Hypothesis: `HYP-0007`
- Slice: `SLICE-0004`
- Harness Package: `HARNESS-0007`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: eBPF
- Trigger Condition: Pointer 'data' is freed more than once without reset or reallocation.
- Fix Suggestion: Set data to NULL after free and enforce single ownership.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from eBPF and needs manual review.

### FINDING-0008 - Heap Buffer Overflow
- File: `uaf_struct_field.c`
- Function: `player_init`
- CWE: `CWE-122`
- Hypothesis: `HYP-0008`
- Slice: `SLICE-0045`
- Harness Package: `HARNESS-0008`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: AFL++, eBPF
- Trigger Condition: Dangerous copy-style operation may write beyond destination bounds.
- Fix Suggestion: Validate input length and use bounded APIs with explicit destination size.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from AFL++, eBPF and needs manual review.

### FINDING-0009 - Possible Buffer Overflow
- File: `uaf_cross_function.c`
- Function: `edit_chunk`
- CWE: `CWE-122`
- Hypothesis: `HYP-0009`
- Slice: `SLICE-0041`
- Harness Package: `HARNESS-0009`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: AFL++, eBPF
- Trigger Condition: Dangerous copy-style operation may write beyond destination bounds.
- Fix Suggestion: Validate input length and use bounded APIs with explicit destination size.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from AFL++, eBPF and needs manual review.

### FINDING-0010 - Heap Buffer Overflow
- File: `uaf_array_slot.c`
- Function: `create_slot`
- CWE: `CWE-122`
- Hypothesis: `HYP-0010`
- Slice: `SLICE-0037`
- Harness Package: `HARNESS-0010`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: AFL++, eBPF
- Trigger Condition: Dangerous copy-style operation may write beyond destination bounds.
- Fix Suggestion: Validate input length and use bounded APIs with explicit destination size.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from AFL++, eBPF and needs manual review.

### FINDING-0011 - Double Free
- File: `double_free_error_path.c`
- Function: `update_profile`
- CWE: `CWE-415`
- Hypothesis: `HYP-0011`
- Slice: `SLICE-0010`
- Harness Package: `HARNESS-0011`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: eBPF
- Trigger Condition: Pointer 'profile' is freed more than once without reset or reallocation.
- Fix Suggestion: Set profile to NULL after free and enforce single ownership.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from eBPF and needs manual review.

### FINDING-0012 - Double Free
- File: `double_free_error_path.c`
- Function: `update_profile`
- CWE: `CWE-415`
- Hypothesis: `HYP-0012`
- Slice: `SLICE-0010`
- Harness Package: `HARNESS-0012`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: eBPF
- Trigger Condition: Pointer 'profile' is freed more than once without reset or reallocation.
- Fix Suggestion: Set profile to NULL after free and enforce single ownership.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from eBPF and needs manual review.

### FINDING-0013 - Double Free
- File: `double_free_direct.c`
- Function: `main`
- CWE: `CWE-415`
- Hypothesis: `HYP-0013`
- Slice: `SLICE-0009`
- Harness Package: `HARNESS-0013`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: eBPF
- Trigger Condition: Pointer 'data' is freed more than once without reset or reallocation.
- Fix Suggestion: Set data to NULL after free and enforce single ownership.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from eBPF and needs manual review.

### FINDING-0014 - Stack Buffer Overflow
- File: `stack_overflow_strcpy.c`
- Function: `set_player_name`
- CWE: `CWE-121`
- Hypothesis: `HYP-0014`
- Slice: `SLICE-0035`
- Harness Package: `HARNESS-0014`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: AFL++
- Trigger Condition: Dangerous copy-style operation may write beyond destination bounds.
- Fix Suggestion: Validate input length and use bounded APIs with explicit destination size.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from AFL++ and needs manual review.

### FINDING-0015 - Stack Buffer Overflow
- File: `stack_overflow_sprintf.c`
- Function: `make_banner`
- CWE: `CWE-121`
- Hypothesis: `HYP-0015`
- Slice: `SLICE-0033`
- Harness Package: `HARNESS-0015`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: AFL++
- Trigger Condition: Dangerous copy-style operation may write beyond destination bounds.
- Fix Suggestion: Validate input length and use bounded APIs with explicit destination size.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from AFL++ and needs manual review.

### FINDING-0016 - Format String Vulnerability
- File: `format_string_snprintf.c`
- Function: `render`
- CWE: `CWE-134`
- Hypothesis: `HYP-0016`
- Slice: `SLICE-0016`
- Harness Package: `HARNESS-0016`
- Dynamic Status: **untriggered**
- Evidence Level: weak
- Evidence Sources: none
- Trigger Condition: A printf-style function appears to use a non-literal format argument.
- Fix Suggestion: Use a constant format string, for example printf("%s", input).
- Final Conclusion: This suspected vulnerability was not triggered in the current dynamic validation run.

### FINDING-0017 - Format String Vulnerability
- File: `format_string_syslog_like.c`
- Function: `tiny_syslog`
- CWE: `CWE-134`
- Hypothesis: `HYP-0017`
- Slice: `SLICE-0018`
- Harness Package: `HARNESS-0017`
- Dynamic Status: **untriggered**
- Evidence Level: weak
- Evidence Sources: none
- Trigger Condition: A printf-style function appears to use a non-literal format argument.
- Fix Suggestion: Use a constant format string, for example printf("%s", input).
- Final Conclusion: This suspected vulnerability was not triggered in the current dynamic validation run.

### FINDING-0018 - Format String Vulnerability
- File: `format_string_printf.c`
- Function: `say`
- CWE: `CWE-134`
- Hypothesis: `HYP-0018`
- Slice: `SLICE-0014`
- Harness Package: `HARNESS-0018`
- Dynamic Status: **untriggered**
- Evidence Level: weak
- Evidence Sources: none
- Trigger Condition: A printf-style function appears to use a non-literal format argument.
- Fix Suggestion: Use a constant format string, for example printf("%s", input).
- Final Conclusion: This suspected vulnerability was not triggered in the current dynamic validation run.

### FINDING-0019 - Format String Vulnerability
- File: `format_string_fprintf.c`
- Function: `log_event`
- CWE: `CWE-134`
- Hypothesis: `HYP-0019`
- Slice: `SLICE-0012`
- Harness Package: `HARNESS-0019`
- Dynamic Status: **untriggered**
- Evidence Level: weak
- Evidence Sources: none
- Trigger Condition: A printf-style function appears to use a non-literal format argument.
- Fix Suggestion: Use a constant format string, for example printf("%s", input).
- Final Conclusion: This suspected vulnerability was not triggered in the current dynamic validation run.

### FINDING-0020 - Stack Buffer Overflow
- File: `stack_overflow_loop.c`
- Function: `copy_loop`
- CWE: `CWE-121`
- Hypothesis: `HYP-0020`
- Slice: `SLICE-0031`
- Harness Package: `HARNESS-0020`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: AFL++
- Trigger Condition: Stack array 'dst[10]' is written with an index that is not locally bounded.
- Fix Suggestion: Validate the index against the stack buffer length before writing.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from AFL++ and needs manual review.

### FINDING-0021 - Stack Buffer Overflow
- File: `stack_overflow_index.c`
- Function: `set_checkpoint`
- CWE: `CWE-121`
- Hypothesis: `HYP-0021`
- Slice: `SLICE-0029`
- Harness Package: `HARNESS-0021`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: AFL++
- Trigger Condition: Stack array 'checkpoints[4]' is written with an index that is not locally bounded.
- Fix Suggestion: Validate the index against the stack buffer length before writing.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from AFL++ and needs manual review.

### FINDING-0022 - Use After Free
- File: `uaf_struct_field.c`
- Function: `main`
- CWE: `CWE-416`
- Hypothesis: `HYP-0022`
- Slice: `SLICE-0047`
- Harness Package: `HARNESS-0022`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: AFL++, eBPF
- Trigger Condition: Expression 'p' is freed and later used through 'local_use'.
- Fix Suggestion: Do not use the object after ownership release; null out aliases or restructure the control flow.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from AFL++, eBPF and needs manual review.

### FINDING-0023 - Double Free
- File: `double_free_alias.c`
- Function: `main`
- CWE: `CWE-415`
- Hypothesis: `HYP-0023`
- Slice: `SLICE-0004`
- Harness Package: `HARNESS-0023`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: eBPF
- Trigger Condition: Memory expression 'owner' is freed after an equivalent expression was already freed.
- Fix Suggestion: Enforce single ownership, clear aliases after free, and avoid freeing the same allocation on multiple paths.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from eBPF and needs manual review.

### FINDING-0024 - Use After Free
- File: `uaf_cross_function.c`
- Function: `main`
- CWE: `CWE-416`
- Hypothesis: `HYP-0024`
- Slice: `SLICE-0042`
- Harness Package: `HARNESS-0024`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: AFL++, eBPF
- Trigger Condition: Expression 'chunk' is freed and later used through 'edit_chunk'.
- Fix Suggestion: Do not use the object after ownership release; null out aliases or restructure the control flow.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from AFL++, eBPF and needs manual review.

### FINDING-0025 - Use After Free
- File: `uaf_array_slot.c`
- Function: `main`
- CWE: `CWE-416`
- Hypothesis: `HYP-0025`
- Slice: `SLICE-0039`
- Harness Package: `HARNESS-0025`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: AFL++, eBPF
- Trigger Condition: Expression 'slots' is freed and later used through 'local_use'.
- Fix Suggestion: Do not use the object after ownership release; null out aliases or restructure the control flow.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from AFL++, eBPF and needs manual review.

### FINDING-0026 - Double Free
- File: `double_free_error_path.c`
- Function: `update_profile`
- CWE: `CWE-415`
- Hypothesis: `HYP-0026`
- Slice: `SLICE-0010`
- Harness Package: `HARNESS-0026`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: eBPF
- Trigger Condition: Memory expression 'profile' is freed after an equivalent expression was already freed.
- Fix Suggestion: Enforce single ownership, clear aliases after free, and avoid freeing the same allocation on multiple paths.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from eBPF and needs manual review.

### FINDING-0027 - Double Free
- File: `double_free_direct.c`
- Function: `main`
- CWE: `CWE-415`
- Hypothesis: `HYP-0027`
- Slice: `SLICE-0009`
- Harness Package: `HARNESS-0027`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: eBPF
- Trigger Condition: Memory expression 'note' is freed after an equivalent expression was already freed.
- Fix Suggestion: Enforce single ownership, clear aliases after free, and avoid freeing the same allocation on multiple paths.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from eBPF and needs manual review.

### FINDING-0028 - Double Free
- File: `double_free_cleanup.c`
- Function: `main`
- CWE: `CWE-415`
- Hypothesis: `HYP-0028`
- Slice: `SLICE-0007`
- Harness Package: `HARNESS-0028`
- Dynamic Status: **need_review**
- Evidence Level: medium
- Evidence Sources: eBPF
- Trigger Condition: Memory expression 'chunk' is freed after an equivalent expression was already freed.
- Fix Suggestion: Enforce single ownership, clear aliases after free, and avoid freeing the same allocation on multiple paths.
- Final Conclusion: This suspected vulnerability has partial runtime evidence from eBPF and needs manual review.
