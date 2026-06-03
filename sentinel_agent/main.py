import argparse
from pathlib import Path

from core.file_scanner import scan_source_files, scan_project_metadata_files
from core.json_utils import save_json, load_json
from core.integration_schema import to_backend_components, to_backend_vulnerabilities

from agents.agent_a_dependency import run_agent_a
from agents.agent_b_slicer import run_agent_b
from agents.agent_c_static_audit import run_agent_c
from agents.agent_d_harness import run_agent_d
from agents.agent_e_final_report import run_agent_e


def run_pipeline(project_path, output_dir="outputs", harness_dir="harness_packages"):
    project_path = Path(project_path).resolve()
    project_name = project_path.name
    output_dir = Path(output_dir).resolve()
    harness_dir = Path(harness_dir).resolve()

    print(f"[0/7] Project: {project_path}")

    print("[1/7] Scanning C/C++ source files and metadata files...")
    source_files = scan_source_files(str(project_path))
    metadata_files = scan_project_metadata_files(str(project_path))
    print(f"      Source files: {len(source_files)}")
    print(f"      Metadata files: {len(metadata_files)}")

    print("[2/7] Agent A: dependency risk identification...")
    agent_a_result = run_agent_a(source_files, metadata_files)
    save_json(agent_a_result, output_dir / "agent_a_components.json")
    save_json(to_backend_components(agent_a_result), output_dir / "agent_a_backend_components.json")

    print("[3/7] Agent B: context pruning and code slicing...")
    agent_b_result = run_agent_b(source_files)
    save_json(agent_b_result, output_dir / "agent_b_slices.json")

    print("[4/7] Agent C: static vulnerability audit...")
    agent_c_result = run_agent_c(agent_a_result, agent_b_result)
    save_json(agent_c_result, output_dir / "agent_c_findings.json")
    save_json(to_backend_vulnerabilities(agent_c_result), output_dir / "agent_c_backend_vulnerabilities.json")

    print("[5/7] Agent D: harness package generation...")
    agent_d_result = run_agent_d(agent_c_result, harness_root=harness_dir, project_root=project_path)
    save_json(agent_d_result, output_dir / "agent_d_harness_packages.json")

    print("[6/7] Loading dynamic validation results...")
    afl_result = load_json(Path("validation") / "afl_result_example.json", default={"crash_found": False})
    ebpf_log = load_json(Path("validation") / "ebpf_log_example.json", default={"events": []})
    asan_result = load_json(Path("validation") / "asan_validation_results.json", default={})

    if asan_result:
        print("      ASan results loaded: "
              f"{asan_result.get('summary', {}).get('confirmed_findings', 0)} confirmed")
    else:
        print("      ASan results not found, using AFL++/eBPF mock compatibility mode.")

    print("[7/7] Agent E: final judgement and report...")
    final_report = run_agent_e(
        project_name=project_name,
        agent_a_result=agent_a_result,
        agent_c_result=agent_c_result,
        agent_d_result=agent_d_result,
        afl_result=afl_result,
        ebpf_log=ebpf_log,
        asan_result=asan_result,
        output_dir=output_dir
    )

    print("\n=== SENTINEL Part 4.2 Finished ===")
    print(f"Project: {final_report['project_name']}")
    print(f"Overall Risk: {final_report['overall_risk']}")
    print(f"Components: {final_report['summary']['total_components']}")
    print(f"Static Findings: {final_report['summary']['total_static_findings']}")
    print(f"Harness Packages: {final_report['summary']['total_harness_packages']}")
    print(f"Confirmed Findings: {final_report['summary']['confirmed_findings']}")
    print(f"ASan Confirmed Findings: {final_report['summary'].get('asan_confirmed_findings', 0)}")
    print(f"Final JSON: {output_dir / 'final_report.json'}")
    print(f"Final MD: {output_dir / 'final_report.md'}")
    return final_report


def main():
    parser = argparse.ArgumentParser(description="SENTINEL - Five-Agent Pipeline")
    parser.add_argument("--project", required=True)
    parser.add_argument("--output", default="outputs")
    parser.add_argument("--harness", default="harness_packages")
    args = parser.parse_args()
    run_pipeline(args.project, args.output, args.harness)


if __name__ == "__main__":
    main()
