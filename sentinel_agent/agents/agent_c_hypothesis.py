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
        slice_hypotheses.extend(detect_format_string(slc, function_lines))

        if not slice_hypotheses:
            skipped_slices.append({
                "slice_id": slc.get("slice_id"),
                "target_file": slc.get("target_file"),
                "target_function": slc.get("target_function"),
                "reason": "No rule-level vulnerability hypothesis generated."
            })
        hypotheses.extend(slice_hypotheses)

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
        "suggested_fix": suggested_fix,
        "vulnerability_type": vulnerability_type,
        "risk_level": risk_level,
    }


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
