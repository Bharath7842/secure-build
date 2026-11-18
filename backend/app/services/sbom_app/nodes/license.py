import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ..collectors.producer import _needs_producer, enrich_producers
from ..graph.state import SBOMState
from ..license.clearlydefined import batch_lookup
from ..license.detector import LicenseDetector
from ..license.verifier import verify_many

logger = logging.getLogger("sbom.graph.license")

_OFF_VALUES = {"0", "off", "false", "no"}


def _verification_enabled() -> bool:
    return os.getenv("SBOM_LICENSE_VERIFY", "").strip().lower() not in _OFF_VALUES


def _process_component(args: tuple) -> dict:
    comp, repo_path, cd_batch_results, detector = args
    try:
        declared = comp.get("license", "")
        purl = comp.get("purl", "")

        if not declared and purl and cd_batch_results.get(purl):
            cd_result = cd_batch_results[purl]
            if cd_result and cd_result.get("spdx_id"):
                comp = {**comp, "_cd_license": cd_result["spdx_id"]}

        license_info = detector.detect_component_license(comp, repo_path)
        classification = detector.classify_component(comp, license_info)

        return {
            "purl": comp.get("purl", ""),
            "name": comp.get("name", ""),
            "version": comp.get("version", ""),
            "spdx_id": license_info.spdx_id,
            "license_name": license_info.name,
            "license_type": license_info.type.value,
            "confidence": license_info.confidence,
            "source": license_info.source,
            "evidence": license_info.evidence,
            "vendor": classification.vendor,
            "edition": classification.edition.value,
            "cost_classification": classification.cost_classification.value,
            "free_features": classification.free_features,
            "paid_features": classification.paid_features,
        }
    except Exception as e:
        logger.warning("License detection failed for %s: %s", comp.get("name", ""), e)
        return {
            "purl": comp.get("purl", ""),
            "name": comp.get("name", ""),
            "version": comp.get("version", ""),
            "spdx_id": "LicenseRef-unknown",
            "license_name": "Unknown License",
            "license_type": "unknown",
            "confidence": 0.0,
            "source": "error",
            "evidence": "license detection failed",
            "vendor": None,
            "edition": "unknown",
            "cost_classification": "unknown",
            "free_features": [],
            "paid_features": [],
        }


def license_node(state: SBOMState) -> dict:
    errors = list(state.get("errors", []))
    components = state.get("components", [])
    repository_path = state.get("repository_path")

    if not components or not repository_path:
        return {"licenses": [], "errors": errors}

    try:
        repo_path = Path(repository_path)

        purls_to_lookup = []
        for comp in components:
            declared = comp.get("license", "")
            purl = comp.get("purl", "")
            if not declared and purl:
                purls_to_lookup.append(purl)

        cd_batch_results = {}
        if purls_to_lookup:
            cd_batch_results = batch_lookup(purls_to_lookup)

        max_workers = min(len(components), 8)
        licenses = []
        needs_producer = any(_needs_producer(comp) for comp in components)

        if max_workers > 1:
            def create_detector():
                return LicenseDetector()

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                detectors = [LicenseDetector() for _ in range(max_workers)]
                try:
                    tasks = []
                    for i, comp in enumerate(components):
                        detector = detectors[i % max_workers]
                        tasks.append((comp, repo_path, cd_batch_results, detector))

                    # Producer enrichment runs alongside license detection so
                    # its registry rate limit overlaps the deps.dev window.
                    futures = {}
                    if needs_producer:
                        futures[executor.submit(enrich_producers, components)] = None
                    for task in tasks:
                        futures[executor.submit(_process_component, task)] = task

                    for future in as_completed(futures):
                        task = futures[future]
                        if task is None:
                            try:
                                components = future.result()
                            except Exception as e:  # noqa: BLE001 - enrichment is best-effort
                                errors.append({"node": "licenses", "error": str(e)})
                            continue
                        try:
                            licenses.append(future.result())
                        except Exception as e:
                            errors.append({"node": "licenses", "error": str(e)})
                finally:
                    for d in detectors:
                        try:
                            d.close()
                        except Exception:
                            pass
        else:
            detector = LicenseDetector()
            try:
                if needs_producer:
                    components = enrich_producers(components)
                for comp in components:
                    try:
                        task = (comp, repo_path, cd_batch_results, detector)
                        licenses.append(_process_component(task))
                    except Exception as e:
                        errors.append({"node": "licenses", "error": str(e)})
            finally:
                detector.close()

    except Exception as e:
        errors.append({"node": "licenses", "error": str(e)})
        licenses = []

    # Post-detection stage: verify declared licenses against the shipped
    # package archives. Flag-only — outcomes are data on each entry, never
    # node errors/warnings (which would gate scan status).
    if licenses and _verification_enabled():
        try:
            verify_many(licenses)
        except Exception as e:  # noqa: BLE001 - verification must not fail the node
            logger.warning("License text verification stage failed: %s", e)

    return {"licenses": licenses, "errors": errors, "components": components}
