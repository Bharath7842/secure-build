from typing import TypedDict


class SBOMState(TypedDict, total=False):
    scan_id: str
    source_type: str
    source_url: str | None
    upload_path: str | None
    repository_path: str | None
    archive_name: str

    # §4 project metadata (never invented — unknown/null when undeterminable)
    project_metadata: dict

    ecosystems: list
    ecosystem_report: list[dict]
    dependency_files: list
    # Raw dependency sightings from the collectors, before normalize.
    dependencies: list
    components: list
    edges: list
    dependency_edges: list
    dependency_graph: dict

    sbom: dict | None
    sboms: dict
    licenses: list
    artifacts: dict

    warnings: list
    errors: list
