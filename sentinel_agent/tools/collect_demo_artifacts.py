import argparse
import json
import shutil
import zipfile
from datetime import datetime
from pathlib import Path


KEY_OUTPUTS = [
    "outputs/final_report.md",
    "outputs/final_report.json",
    "outputs/agent_a_components.json",
    "outputs/agent_b_slices.json",
    "outputs/agent_c_findings.json",
    "outputs/agent_d_harness_packages.json",
    "validation/asan_validation_results.json",
]

KEY_DOCS = [
    "docs/part4_2_asan_to_agent_e.md",
    "docs/agent_d_part4_1_asan_validation.md",
    "docs/agent_c_part3_2_quality_control.md",
]


def main():
    parser = argparse.ArgumentParser(description="Collect SENTINEL demo artifacts.")
    parser.add_argument("--project-root", default=".", help="SENTINEL project root.")
    parser.add_argument("--output-dir", default="demo_artifacts", help="Artifact output directory.")
    args = parser.parse_args()

    root = Path(args.project_root).resolve()
    out_dir = root / args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    package_dir = out_dir / f"sentinel_demo_artifacts_{stamp}"
    package_dir.mkdir(parents=True, exist_ok=True)

    copy_selected_files(root, package_dir)
    copy_asan_logs(root, package_dir)
    write_summary(root, package_dir)

    zip_path = out_dir / f"{package_dir.name}.zip"
    zip_directory(package_dir, zip_path)

    print(f"Artifact directory: {package_dir}")
    print(f"Artifact zip: {zip_path}")


def copy_selected_files(root: Path, package_dir: Path):
    for rel in KEY_OUTPUTS + KEY_DOCS:
        src = root / rel
        if not src.exists():
            continue
        dst = package_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def copy_asan_logs(root: Path, package_dir: Path):
    log_dst = package_dir / "asan_logs"
    log_dst.mkdir(parents=True, exist_ok=True)

    for log in sorted((root / "harness_packages").glob("HARNESS-*/*.log")):
        harness_name = log.parent.name
        dst = log_dst / f"{harness_name}_{log.name}"
        shutil.copy2(log, dst)


def write_summary(root: Path, package_dir: Path):
    final_report = load_json(root / "outputs/final_report.json")
    asan_result = load_json(root / "validation/asan_validation_results.json")

    summary = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "project_root": str(root),
        "final_summary": final_report.get("summary", {}),
        "overall_risk": final_report.get("overall_risk"),
        "asan_summary": asan_result.get("summary", {}),
        "final_findings": [
            {
                "finding_id": f.get("finding_id"),
                "file": f.get("file"),
                "function": f.get("function"),
                "cwe_id": f.get("cwe_id"),
                "vulnerability_type": f.get("vulnerability_type"),
                "dynamic_status": f.get("dynamic_status"),
                "asan_bug_type": (f.get("asan_evidence") or {}).get("asan_bug_type"),
                "asan_consistency": (f.get("asan_evidence") or {}).get("consistency"),
            }
            for f in final_report.get("final_findings", [])
        ],
    }

    (package_dir / "SUMMARY.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    lines = []
    lines.append("# SENTINEL Demo Artifact Summary")
    lines.append("")
    lines.append(f"- Generated at: {summary['generated_at']}")
    lines.append(f"- Overall risk: **{summary.get('overall_risk')}**")
    fs = summary.get("final_summary", {})
    lines.append(f"- Components: {fs.get('total_components')}")
    lines.append(f"- Static findings: {fs.get('total_static_findings')}")
    lines.append(f"- Harness packages: {fs.get('total_harness_packages')}")
    lines.append(f"- Confirmed findings: {fs.get('confirmed_findings')}")
    lines.append(f"- ASan confirmed findings: {fs.get('asan_confirmed_findings')}")
    lines.append("")
    lines.append("## Final Findings")
    for f in summary["final_findings"]:
        lines.append(
            f"- {f['finding_id']} | {f['cwe_id']} | {f['vulnerability_type']} | "
            f"{f['asan_bug_type']} | {f['dynamic_status']}"
        )
    lines.append("")
    (package_dir / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")


def load_json(path: Path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def zip_directory(src_dir: Path, zip_path: Path):
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in src_dir.rglob("*"):
            if p.is_file():
                z.write(p, p.relative_to(src_dir.parent))


if __name__ == "__main__":
    main()
