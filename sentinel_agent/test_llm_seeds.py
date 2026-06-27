#!/usr/bin/env python3
"""
Test LLM seed generation functionality
"""

import sys
from pathlib import Path

# Add agent root to path
AGENT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(AGENT_ROOT))

from agents.agent_d_harness import generate_seeds_with_llm
from core.llm_client import LLMClient


def test_llm_seed_generation():
    """Test LLM-based seed generation"""

    print("=" * 60)
    print("Testing LLM Seed Generation")
    print("=" * 60)

    # Check LLM availability
    llm = LLMClient()
    if not llm.is_available():
        print("❌ LLM not configured. Please set LLM_API_KEY, LLM_BASE_URL, LLM_MODEL in .env")
        return False

    print(f"✓ LLM configured: {llm.model}")
    print()

    # Test case: Stack overflow vulnerability
    finding = {
        "finding_id": "VULN-001",
        "file": "src/modbus_proto.c",
        "function": "modbus_handle_fc17",
        "line_range": "144-152",
        "vulnerability_type": "Stack-based Buffer Overflow",
        "cwe_id": "CWE-121",
        "trigger_condition": "When nb_read >= 60, response buffer overflows (128 bytes fixed buffer, but response can be up to 259 bytes)",
    }

    strategy = {
        "argument_model": "modbus_request_struct",
        "entry_point": "modbus_handle_fc17",
    }

    project_root = AGENT_ROOT / "samples" / "level2_testset" / "03_modbus_stackoverflow"

    print("Test Case: Modbus Stack Overflow (CWE-121)")
    print(f"  Function: {finding['function']}")
    print(f"  Trigger: {finding['trigger_condition'][:80]}...")
    print()

    print("Calling LLM to generate seeds...")
    seeds = generate_seeds_with_llm(finding, strategy, project_root)

    if not seeds:
        print("❌ LLM failed to generate seeds")
        return False

    print(f"✓ LLM generated {len(seeds)} seed files:")
    print()

    for name, content in seeds.items():
        print(f"  📄 {name}")
        print(f"     Size: {len(content)} bytes")
        print(f"     Preview: {content[:40].hex()}{'...' if len(content) > 40 else ''}")
        print()

    print("=" * 60)
    print("✓ Test passed: LLM seed generation working")
    print("=" * 60)

    return True


if __name__ == "__main__":
    success = test_llm_seed_generation()
    sys.exit(0 if success else 1)
