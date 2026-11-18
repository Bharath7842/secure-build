"""Policy testing framework.

Provides positive/negative test support for internal queries.
Tests can be defined in metadata.yaml or in separate test files.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

from app.services.iac_app.domain.document import NormalizedDocument, NormalizedResource


class PolicyTestRunner:
    """Run positive/negative tests for policy rules."""

    def __init__(self, queries_dir: str | Path | None = None) -> None:
        if queries_dir:
            self._queries_dir = Path(queries_dir)
        else:
            self._queries_dir = Path(__file__).resolve().parents[3] / "queries"

    def run_tests(self, rule_id: str) -> dict[str, Any]:
        """Run tests for a specific rule."""
        rule_dir = self._find_rule_dir(rule_id)
        if not rule_dir:
            return {"error": f"Rule directory not found for {rule_id}"}

        metadata = self._load_metadata(rule_dir)
        test_cases = self._load_test_cases(rule_dir)
        evaluate = self._load_evaluate(rule_dir)

        if not evaluate:
            return {"error": f"Could not load evaluate function for {rule_id}"}

        results = {
            "rule_id": rule_id,
            "total": len(test_cases),
            "passed": 0,
            "failed": 0,
            "tests": [],
        }

        for test in test_cases:
            test_result = self._run_single_test(evaluate, test)
            results["tests"].append(test_result)
            if test_result["passed"]:
                results["passed"] += 1
            else:
                results["failed"] += 1

        results["success"] = results["failed"] == 0
        return results

    def run_all_tests(self) -> dict[str, Any]:
        """Run tests for all rules."""
        results = {"total_rules": 0, "passed_rules": 0, "failed_rules": 0, "rules": []}

        for metadata_path in sorted(self._queries_dir.rglob("metadata.yaml")):
            rule_dir = metadata_path.parent
            metadata = self._load_metadata(rule_dir)
            if not metadata:
                continue

            rule_id = metadata.get("id", "")
            test_result = self.run_tests(rule_id)
            results["rules"].append(test_result)
            results["total_rules"] += 1
            if test_result.get("success", False):
                results["passed_rules"] += 1
            else:
                results["failed_rules"] += 1

        results["success"] = results["failed_rules"] == 0
        return results

    def _find_rule_dir(self, rule_id: str) -> Path | None:
        for metadata_path in self._queries_dir.rglob("metadata.yaml"):
            try:
                content = metadata_path.read_text(encoding="utf-8")
                for line in content.splitlines():
                    if line.startswith("id:") and rule_id in line:
                        return metadata_path.parent
            except Exception:
                continue
        return None

    def _load_metadata(self, rule_dir: Path) -> dict | None:
        metadata_path = rule_dir / "metadata.yaml"
        if not metadata_path.exists():
            return None
        try:
            import yaml
            return yaml.safe_load(metadata_path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def _load_evaluate(self, rule_dir: Path):
        rule_path = rule_dir / "rule.py"
        if not rule_path.exists():
            return None
        try:
            spec = importlib.util.spec_from_file_location("rule_module", str(rule_path))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return getattr(module, "evaluate", None)
        except Exception:
            return None

    def _load_test_cases(self, rule_dir: Path) -> list[dict[str, Any]]:
        """Load test cases from tests/ subdirectory or test.yaml."""
        test_cases = []

        test_yaml = rule_dir / "test.yaml"
        if test_yaml.exists():
            try:
                import yaml
                data = yaml.safe_load(test_yaml.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    for tc in data.get("tests", []):
                        test_cases.append({
                            "name": tc.get("name", "unnamed"),
                            "content": tc.get("content", ""),
                            "type": tc.get("type", "terraform"),
                            "expected": tc.get("expected", True),
                        })
            except Exception:
                pass

        test_dir = rule_dir / "tests"
        if test_dir.is_dir():
            for test_file in sorted(test_dir.glob("*.tf")):
                test_cases.append({
                    "name": test_file.stem,
                    "content": test_file.read_text(encoding="utf-8"),
                    "type": "terraform",
                    "expected": True,
                })
            for test_file in sorted(test_dir.glob("*.negative.tf")):
                test_cases.append({
                    "name": test_file.stem,
                    "content": test_file.read_text(encoding="utf-8"),
                    "type": "terraform",
                    "expected": False,
                })

        return test_cases

    def _run_single_test(self, evaluate, test: dict[str, Any]) -> dict[str, Any]:
        """Run a single test case."""
        try:
            content = test.get("content", "")
            doc = self._create_test_document(content, test.get("type", "terraform"))
            findings = evaluate(doc)
            has_findings = len(findings) > 0
            expected = test.get("expected", True)
            passed = has_findings == expected
            return {
                "name": test.get("name", "unnamed"),
                "passed": passed,
                "expected_findings": expected,
                "actual_findings": has_findings,
                "finding_count": len(findings),
                "error": None,
            }
        except Exception as exc:
            return {
                "name": test.get("name", "unnamed"),
                "passed": False,
                "expected_findings": test.get("expected", True),
                "actual_findings": False,
                "finding_count": 0,
                "error": str(exc),
            }

    def _create_test_document(self, content: str, doc_type: str) -> dict:
        """Create a test document from content string."""
        if doc_type == "terraform":
            return self._create_terraform_doc(content)
        elif doc_type == "kubernetes":
            return self._create_kubernetes_doc(content)
        elif doc_type == "docker":
            return self._create_docker_doc(content)
        return {"resources": []}

    def _create_terraform_doc(self, content: str) -> dict:
        """Create a Terraform test document."""
        resources = []
        import re
        for match in re.finditer(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}', content, re.DOTALL):
            resource_type = match.group(1)
            resource_name = match.group(2)
            block = match.group(3)

            attrs = {}
            for attr_match in re.finditer(r'(\w+)\s*=\s*(.+?)(?:\n|$)', block):
                attr_name = attr_match.group(1)
                attr_value = attr_match.group(2).strip().strip('"')
                if attr_value.lower() == "true":
                    attrs[attr_name] = True
                elif attr_value.lower() == "false":
                    attrs[attr_name] = False
                else:
                    attrs[attr_name] = attr_value

            resources.append({
                "id": f"{resource_type}.{resource_name}",
                "type": resource_type,
                "name": resource_name,
                "attributes": attrs,
                "location": {"line_start": content[:match.start()].count("\n") + 1},
            })

        return {"resources": resources}

    def _create_kubernetes_doc(self, content: str) -> dict:
        """Create a Kubernetes test document."""
        import yaml
        try:
            doc = yaml.safe_load(content)
            if isinstance(doc, dict):
                return {
                    "resources": [{
                        "id": doc.get("metadata", {}).get("name", "test"),
                        "type": doc.get("kind", "Unknown"),
                        "name": doc.get("metadata", {}).get("name", "test"),
                        "attributes": doc,
                        "location": {"line_start": 1},
                    }]
                }
        except Exception:
            pass
        return {"resources": []}

    def _create_docker_doc(self, content: str) -> dict:
        """Create a Docker test document."""
        return {
            "resources": [{
                "id": "Dockerfile",
                "type": "dockerfile",
                "name": "Dockerfile",
                "attributes": {"content": content},
                "location": {"line_start": 1},
            }]
        }
