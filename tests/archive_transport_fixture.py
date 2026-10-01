"""Production-shaped, non-live archive transport input for #290."""

import base64
import hashlib
from pathlib import Path

from agent_controller import private_ci_burned_evidence_archive as archive


def rendered_production_bootstrap():
    root = Path(__file__).resolve().parents[1]
    sources = tuple(
        archive.ControllerSourceBinding(
            relative_path=relative,
            sha256=hashlib.sha256(root.joinpath(relative).read_bytes()).hexdigest(),
            size=root.joinpath(relative).stat().st_size,
        )
        for relative in archive.REVIEWED_CONTROLLER_SOURCE_PATHS
    )
    # Full supported production inventory, including later Phase 4/5 slots.
    # Digests are distinct placeholders, not low-entropy repeated hex.
    items = tuple(
        archive.ArchiveItem(
            filename=name,
            sha256=hashlib.sha256(name.encode()).hexdigest(),
            size=10000 + index,
        )
        for index, name in enumerate(archive.CANONICAL_RESTART_BLOCKING_FILENAMES)
    )
    inventory = hashlib.sha256(archive._inventory_bytes(items)).hexdigest()
    plan = archive.ArchivePlan(
        schema=archive.ARCHIVE_PLAN_SCHEMA,
        evidence_root=r"C:\Users\Public\Documents\agent-controller-handoff",
        controller_main_sha="923f8ca5cd1ab9759db400da32132c08da3ae666",
        controller_tree=r"C:\Users\operator\agent-controller-pilot-216",
        python_executable=r"C:\Program Files\Python312\python.exe",
        python_sha256=hashlib.sha256(b"trusted-python-runtime").hexdigest(),
        controller_sources=sources,
        inventory_sha256=inventory,
        archive_directory="archive/issue216-burned-" + inventory[:16],
        items=items,
    )
    raw = archive.archive_plan_bytes(plan)
    archive.parse_archive_plan_bytes(raw)
    source = root.joinpath(sources[0].relative_path).read_bytes().decode("utf-8")
    return source.replace(
        "__EXPECTED_PLAN_SHA256__", hashlib.sha256(raw).hexdigest()
    ).replace("__EXPECTED_PLAN_BASE64__", base64.b64encode(raw).decode("ascii"))
