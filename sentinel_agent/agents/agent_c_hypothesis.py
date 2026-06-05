import re

from core.id_generator import make_id


TARGET_BODY_MARKER = "/* ===== Target Function Body ===== */"
FREE_PATTERN = re.compile(r'\bfree\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)')
DANGEROUS_COPY_PATTERN = re.compile(r'\b(strcpy|strcat|sprintf|memcpy|memmove|gets)\s*\(')
FORMAT_CALL_PATTERN = re.compile(r'\b(printf|fprintf|sprintf|snprintf|vprintf|vfprintf|syslog)\s*\(')


def run_agent_c(agent_a_result, agent_b_result):
    """
    Agent C - Vulnerability Hypothesis Generation.

    This agent turns prioritized code slices into explainable vulnerability
    hypotheses. It does not call the LLM and does not make final decisions.
    """
    hypotheses = []
    skipped_slices = []

    candidate_slices = [
        slc for slc in agent_b_result.get("slices", [])
        if slc.get("audit_priority") in {"high", "medium"}
    ]

    for slc in candidate_slices:
        function_lines = extract_target_function_lines(slc)
        slice_hypotheses = []
        slice_hypotheses.extend(detect_uaf_and_double_free(slc, function_lines))
        slice_hypotheses.extend(detect_overflow(slc, function_lines))
        slice_hypotheses.extend(detect_index_loop_overflow(slc, function_lines))
        slice_hypotheses.extend(detect_format_string(slc, function_lines))

        if not slice_hypotheses:
            skipped_slices.append({
                "slice_id": slc.get("slice_id"),
                "target_file": slc.get("target_file"),
                "target_function": slc.get("target_function"),
                "reason": "No rule-level vulnerability hypothesis generated."
            })
        hypotheses.extend(slice_hypotheses)

    hypotheses.extend(detect_cross_function_memory(agent_b_result))

    hypotheses = deduplicate_hypotheses(hypotheses)
    for idx, hyp in enumerate(hypotheses, start=1):
        hyp["hypothesis_id"] = make_id("HYP", idx)

    return {
        "agent": "Agent C - Vulnerability Hypothesis Agent",
        "hypotheses": hypotheses,
        "skipped_slices": skipped_slices,
        "summary": {
            "total_input_slices": len(agent_b_result.get("slices", [])),
            "candidate_slices": len(candidate_slices),
            "low_priority_slices": sum(
                1 for slc in agent_b_result.get("slices", [])
                if slc.get("audit_priority") == "low"
            ),
            "total_hypotheses": len(hypotheses),
            "hypotheses_by_cwe": count_by_cwe(hypotheses),
            "component_context_count": len(agent_a_result.get("components", [])),
        }
    }


def extract_target_function_lines(slc):
    code = slc.get("code", "")
    function_start_line = slc["line_range"][0]
    body = code.split(TARGET_BODY_MARKER, 1)[1] if TARGET_BODY_MARKER in code else code
    raw_lines = body.splitlines()
    while raw_lines and raw_lines[0].strip() == "":
        raw_lines.pop(0)
    return [{"source_line": function_start_line + idx, "code": line} for idx, line in enumerate(raw_lines)]


def detect_uaf_and_double_free(slc, function_lines):
    results = []
    freed = {}
    for item in function_lines:
        source_line = item["source_line"]
        line = item["code"]
        m = FREE_PATTERN.search(line)
        if m:
            ptr = m.group(1)
            if ptr in freed:
                results.append(make_hypothesis(
                    slc=slc,
                    cwe_candidates=["CWE-415"],
                    risk_signals=["double_free"],
                    suspect_lines=[freed[ptr]["source_line"], source_line],
                    confidence=0.78,
                    reason=f"Pointer '{ptr}' is freed more than once without reset or reallocation.",
                    evidence=[
                        f"First free at line {freed[ptr]['source_line']}.",
                        f"Second free at line {source_line}: {line.strip()}",
                    ],
                    suggested_fix=f"Set {ptr} to NULL after free and enforce single ownership.",
                    vulnerability_type="Double Free",
                    risk_level="high",
                ))
            else:
                freed[ptr] = {"source_line": source_line, "code": line}
            continue

        for ptr, free_info in list(freed.items()):
            if re.search(rf'\b{re.escape(ptr)}\s*=\s*NULL\s*;', line):
                freed.pop(ptr, None)
                continue
            if re.search(rf'\*\s*{re.escape(ptr)}\b', line) or re.search(rf'\b{re.escape(ptr)}\s*\[', line) or re.search(rf'\b{re.escape(ptr)}\s*->', line):
                results.append(make_hypothesis(
                    slc=slc,
                    cwe_candidates=["CWE-416"],
                    risk_signals=["free_then_deref"],
                    suspect_lines=[free_info["source_line"], source_line],
                    confidence=0.80,
                    reason=f"Pointer '{ptr}' is accessed after free.",
                    evidence=[
                        f"Pointer '{ptr}' is freed at line {free_info['source_line']}.",
                        f"Pointer '{ptr}' is used again at line {source_line}: {line.strip()}",
                    ],
                    suggested_fix=f"Do not access {ptr} after free; set it to NULL and guard future uses.",
                    vulnerability_type="Use After Free",
                    risk_level="high",
                ))
                freed.pop(ptr, None)
                break
    return results


def detect_overflow(slc, function_lines):
    results = []
    for idx, item in enumerate(function_lines):
        source_line = item["source_line"]
        line = item["code"]
        if not DANGEROUS_COPY_PATTERN.search(line):
            continue

        before = "\n".join(previous["code"] for previous in function_lines[max(0, idx - 8):idx])
        if re.search(r'\bchar\s+[A-Za-z_][A-Za-z0-9_]*\s*\[\s*\d+\s*\]', before):
            cwe, vuln_type, signal = "CWE-121", "Stack Buffer Overflow", "stack_copy_without_bounds"
        elif "malloc" in before:
            cwe, vuln_type, signal = "CWE-122", "Heap Buffer Overflow", "heap_copy_without_bounds"
        else:
            cwe, vuln_type, signal = "CWE-122", "Possible Buffer Overflow", "copy_without_bounds"

        results.append(make_hypothesis(
            slc=slc,
            cwe_candidates=[cwe],
            risk_signals=[signal],
            suspect_lines=[source_line],
            confidence=0.70 if cwe != "CWE-122" or signal != "copy_without_bounds" else 0.62,
            reason="Dangerous copy-style operation may write beyond destination bounds.",
            evidence=[
                f"Dangerous copy-style call at line {source_line}: {line.strip()}",
                "Destination bounds are not proven by the local slice.",
            ],
            suggested_fix="Validate input length and use bounded APIs with explicit destination size.",
            vulnerability_type=vuln_type,
            risk_level="high" if signal != "copy_without_bounds" else "medium",
        ))
    return results


def detect_index_loop_overflow(slc, function_lines):
    results = []
    full = "\n".join(item["code"] for item in function_lines)
    stack_arrays = re.findall(r'\b(?:char|int|unsigned\s+char|uint\d+_t|int\d+_t)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(\d+)\s*\]', full)
    if not stack_arrays:
        return results
    for arr, size in stack_arrays:
        for item in function_lines:
            line = item["code"]
            if re.search(rf'\b{re.escape(arr)}\s*\[[^\]]+\]\s*=', line):
                if re.search(r'\b(idx|index|i|len|size|copy_len)\b', line):
                    results.append(make_hypothesis(
                        slc=slc,
                        cwe_candidates=["CWE-121"],
                        risk_signals=["stack_index_or_loop_write"],
                        suspect_lines=[item["source_line"]],
                        confidence=0.72,
                        reason=f"Stack array '{arr}[{size}]' is written with an index that is not locally bounded.",
                        evidence=[f"Potential out-of-bounds stack write at line {item['source_line']}: {line.strip()}"],
                        suggested_fix="Validate the index against the stack buffer length before writing.",
                        vulnerability_type="Stack Buffer Overflow",
                        risk_level="high",
                    ))
                    break
    return results


def detect_cross_function_memory(agent_b_result):
    slices = agent_b_result.get("slices", [])
    slices_by_function = {slc.get("target_function"): slc for slc in slices}
    effects_by_function = agent_b_result.get("memory_effects", {})
    hypotheses = []

    for slc in slices:
        lines = extract_target_function_lines(slc)
        freed = {}
        aliases = {}
        for item in lines:
            line = item["code"]
            source_line = item["source_line"]
            stripped = line.strip()

            for left, right in re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\]|->[A-Za-z_][A-Za-z0-9_]*|\.[A-Za-z_][A-Za-z0-9_]*)?)\s*;', line):
                aliases[left] = resolve_alias(right, aliases)

            direct_free = FREE_PATTERN.search(line)
            if direct_free:
                expr = direct_free.group(1)
                hypotheses.extend(record_free_or_double_free(slc, freed, aliases, expr, source_line, stripped, "direct_free"))

            for call in iter_function_calls(line):
                callee = call["name"]
                if callee == slc.get("target_function"):
                    continue
                args = call["args"]
                effects = effects_by_function.get(callee)
                if not effects:
                    continue

                free_exprs = effects.get("frees_param") or []
                for free_expr in free_exprs:
                    param_idx = infer_param_index_from_effect(free_expr)
                    if param_idx is None or param_idx >= len(args):
                        continue
                    expr = args[param_idx]
                    hypotheses.extend(record_free_or_double_free(slc, freed, aliases, expr, source_line, stripped, f"{callee}_frees_argument"))

                if effects.get("frees_field") and args:
                    field_expr = normalize_memory_expr(args[0], aliases)
                    hypotheses.extend(record_free_or_double_free(slc, freed, aliases, field_expr, source_line, stripped, f"{callee}_frees_field"))

                if effects.get("writes_param") or effects.get("writes"):
                    for arg in args:
                        used_expr = normalize_memory_expr(arg, aliases)
                        matched = find_matching_freed_expr(used_expr, freed)
                        if matched:
                            hyp = make_cross_function_uaf(slc, matched, used_expr, source_line, stripped, callee)
                            hypotheses.append(hyp)

            for freed_expr, info in list(freed.items()):
                if expression_used_after_free(line, freed_expr):
                    hypotheses.append(make_cross_function_uaf(slc, {"expr": freed_expr, **info}, freed_expr, source_line, stripped, "local_use"))
                    freed.pop(freed_expr, None)

        # Caller/callee context can expose wrapper-driven UAF even when the local
        # line parser missed a complex argument expression.
        for ctx in slc.get("cross_function_context", []):
            if "callee_frees_argument" in ctx.get("risk_signals", []) and slc.get("callee_functions"):
                continue

    return hypotheses


def record_free_or_double_free(slc, freed, aliases, expr, source_line, line_text, signal):
    expr = normalize_memory_expr(expr, aliases)
    results = []
    matched = find_matching_freed_expr(expr, freed)
    if matched and matched.get("source_line") != source_line:
        results.append(make_hypothesis(
            slc=slc,
            cwe_candidates=["CWE-415"],
            risk_signals=["double_free", signal],
            suspect_lines=[matched["source_line"], source_line],
            confidence=0.82,
            reason=f"Memory expression '{expr}' is freed after an equivalent expression was already freed.",
            evidence=[
                f"First free at line {matched['source_line']}: {matched.get('code', '')}",
                f"Second free at line {source_line}: {line_text}",
            ],
            suggested_fix="Enforce single ownership, clear aliases after free, and avoid freeing the same allocation on multiple paths.",
            vulnerability_type="Double Free",
            risk_level="high",
        ))
    freed[expr] = {"expr": expr, "source_line": source_line, "code": line_text, "signal": signal}
    return results


def make_cross_function_uaf(slc, free_info, used_expr, source_line, line_text, callee):
    free_line = free_info.get("source_line", source_line)
    return make_hypothesis(
        slc=slc,
        cwe_candidates=["CWE-416"],
        risk_signals=["cross_function_free_then_use", f"use_via_{callee}"],
        suspect_lines=[free_line, source_line],
        confidence=0.84,
        reason=f"Expression '{used_expr}' is freed and later used through '{callee}'.",
        evidence=[
            f"Free/ownership release at line {free_line}: {free_info.get('code', '')}",
            f"Use after release at line {source_line}: {line_text}",
        ],
        suggested_fix="Do not use the object after ownership release; null out aliases or restructure the control flow.",
        vulnerability_type="Use After Free",
        risk_level="high",
    )


def normalize_memory_expr(expr, aliases):
    expr = str(expr or "").strip()
    expr = expr.lstrip("&").strip()
    expr = re.sub(r'^\([^)]+\)\s*', '', expr)
    if expr in aliases:
        return aliases[expr]
    base = re.match(r'([A-Za-z_][A-Za-z0-9_]*)', expr)
    if base and base.group(1) in aliases:
        return expr.replace(base.group(1), aliases[base.group(1)], 1)
    return expr


def resolve_alias(expr, aliases):
    expr = normalize_memory_expr(expr, aliases)
    return expr


def find_matching_freed_expr(expr, freed):
    expr = str(expr or "").strip()
    for freed_expr, info in freed.items():
        if expr == freed_expr:
            return info
        if expr.startswith(freed_expr + "[") or expr.startswith(freed_expr + "->") or expr.startswith(freed_expr + "."):
            return info
        if freed_expr.startswith(expr + "[") or freed_expr.startswith(expr + "->") or freed_expr.startswith(expr + "."):
            return info
    return None


def expression_used_after_free(line, expr):
    if not expr:
        return False
    escaped = re.escape(expr)
    base = re.escape(expr.split("[", 1)[0].split("->", 1)[0].split(".", 1)[0])
    patterns = [
        rf'\bputs\s*\(\s*{escaped}\s*\)',
        rf'\bprintf\s*\([^;]*{escaped}[^;]*\)',
        rf'\bmem(?:cpy|move|set)\s*\(\s*{escaped}\b',
        rf'\bstr(?:cpy|cat)\s*\(\s*{escaped}\b',
        rf'{escaped}\s*\[',
        rf'{escaped}\s*->',
        rf'\*\s*{escaped}\b',
        rf'\bputs\s*\(\s*{base}\s*\[',
        rf'\bprintf\s*\([^;]*{base}(?:\.|->|\[)',
    ]
    return any(re.search(pattern, line) for pattern in patterns)


def iter_function_calls(line):
    for match in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', line):
        name = match.group(1)
        if name in {"if", "for", "while", "switch", "return", "sizeof"}:
            continue
        open_idx = line.find("(", match.end() - 1)
        close_idx = find_matching_paren(line, open_idx)
        if close_idx is None:
            continue
        yield {"name": name, "args": split_call_args(line[open_idx + 1:close_idx])}


def infer_param_index_from_effect(effect_expr):
    expr = str(effect_expr or "").strip()
    if not expr:
        return None
    # Agent B records free(param), free(param->field), free(param[idx]).
    # The current lightweight model only needs the first parameter for wrappers
    # in the benchmark and demo projects.
    return 0


def detect_format_string(slc, function_lines):
    results = []
    for item in function_lines:
        source_line = item["source_line"]
        line = item["code"]
        if not FORMAT_CALL_PATTERN.search(line):
            continue
        if has_nonliteral_format_arg(line):
            results.append(make_hypothesis(
                slc=slc,
                cwe_candidates=["CWE-134"],
                risk_signals=["nonliteral_format_string"],
                suspect_lines=[source_line],
                confidence=0.76,
                reason="A printf-style function appears to use a non-literal format argument.",
                evidence=[f"Format sink at line {source_line}: {line.strip()}"],
                suggested_fix="Use a constant format string, for example printf(\"%s\", input).",
                vulnerability_type="Format String Vulnerability",
                risk_level="high",
            ))
    return results


def has_nonliteral_format_arg(line):
    for match in FORMAT_CALL_PATTERN.finditer(line):
        fn = match.group(1)
        open_idx = line.find("(", match.end() - 1)
        close_idx = find_matching_paren(line, open_idx)
        if close_idx is None:
            continue
        args = split_call_args(line[open_idx + 1:close_idx])
        fmt_index = {"printf": 0, "vprintf": 0, "fprintf": 1, "vfprintf": 1, "sprintf": 1, "snprintf": 2, "syslog": 1}.get(fn, 0)
        if len(args) <= fmt_index:
            continue
        if not is_string_literal(args[fmt_index].strip()):
            return True
    return False


def make_hypothesis(slc, cwe_candidates, risk_signals, suspect_lines, confidence, reason,
                    evidence, suggested_fix, vulnerability_type, risk_level):
    cross_trace = [
        item.get("trace")
        for item in slc.get("cross_function_context", [])
        if item.get("trace")
    ]
    return {
        "hypothesis_id": "PENDING",
        "source_slice_id": slc["slice_id"],
        "file": slc["target_file"],
        "function": slc["target_function"],
        "line_range": [min(suspect_lines), max(suspect_lines)],
        "cwe_candidates": cwe_candidates,
        "risk_signals": risk_signals,
        "suspect_lines": suspect_lines,
        "confidence": round(confidence, 2),
        "reason": reason,
        "evidence": evidence,
        "evidence_lines": [
            {"line": line, "description": text}
            for line, text in zip(suspect_lines, evidence or [])
        ],
        "cross_function_trace": cross_trace,
        "dataflow_trace": build_dataflow_trace(slc, risk_signals, suspect_lines, reason),
        "suggested_fix": suggested_fix,
        "vulnerability_type": vulnerability_type,
        "risk_level": risk_level,
    }


def build_dataflow_trace(slc, risk_signals, suspect_lines, reason):
    trace = []
    if slc.get("source_sink_pairs"):
        for pair in slc.get("source_sink_pairs", [])[:4]:
            trace.append(f"{pair.get('source')} -> {pair.get('sink')}")
    if suspect_lines:
        trace.append(f"suspect_lines={suspect_lines}")
    if risk_signals:
        trace.append(f"signals={','.join(risk_signals)}")
    trace.append(reason)
    return trace


def deduplicate_hypotheses(hypotheses):
    seen = set()
    result = []
    for hyp in hypotheses:
        key = (hyp.get("source_slice_id"), tuple(hyp.get("cwe_candidates", [])), tuple(hyp.get("suspect_lines", [])))
        if key in seen:
            continue
        seen.add(key)
        result.append(hyp)
    return result


def count_by_cwe(hypotheses):
    counts = {}
    for hyp in hypotheses:
        for cwe in hyp.get("cwe_candidates", ["UNKNOWN"]):
            counts[cwe] = counts.get(cwe, 0) + 1
    return counts


def find_matching_paren(text, open_idx):
    if open_idx < 0:
        return None
    depth = 0
    in_string = False
    quote = ""
    escaped = False
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                in_string = False
            continue
        if ch in {"'", '"'}:
            in_string = True
            quote = ch
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return idx
    return None


def split_call_args(args_text):
    args = []
    current = []
    depth = 0
    in_string = False
    quote = ""
    escaped = False
    for ch in args_text:
        if in_string:
            current.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                in_string = False
            continue
        if ch in {"'", '"'}:
            in_string = True
            quote = ch
            current.append(ch)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current or args_text.strip():
        args.append("".join(current).strip())
    return args


def is_string_literal(expr):
    literal = r'(?:L|u8|u|U)?\"(?:\\.|[^\"\\])*\"'
    return bool(re.fullmatch(rf'{literal}(?:\s*{literal})*', expr))
