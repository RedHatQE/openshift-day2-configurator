from __future__ import annotations
import logging
from typing import Any, Dict

from kubernetes.dynamic import DynamicClient
from rich.progress import Progress, TaskID
from rich.table import Table

from openshift_day2_configurator.configurators.mappings import configurators_mappings


def execute_configurators(
    day2_configurators: Dict[str, Any],
    table: Table,
    logger: logging.Logger,
    client: DynamicClient,
    cluster_domain: str,
    progress: Progress | None = None,
    task_progress: int | None = None,
) -> Table:
    failed_str = "[red]Failed[not red]"
    _configurators_mappings = configurators_mappings()

    task: TaskID | None = None
    if progress:
        task_progress = 1
        task = progress.add_task(
            "[green]Executing Day2 configurations ",
            total=len(day2_configurators),
        )

    for configurator_name, config in day2_configurators.items():
        if configurator_name not in _configurators_mappings:
            table.add_row(
                configurator_name,
                "Missing keys in configuration file",
                failed_str,
                "Missing configurator mapping in configuration file",
            )
            continue

        if configurator_name in ["ingress", "nodes"]:
            config.update({"cluster_domain": cluster_domain})

        for result_str, result_status in _configurators_mappings[configurator_name](
            config=config, logger=logger, progress=progress, client=client
        ).items():
            if progress and task is not None:
                progress.update(task, advance=task_progress, refresh=True)

            status: str = "Passed" if result_status["res"] else failed_str
            reason: str = "" if result_status["res"] else result_status["err"]
            table.add_row(configurator_name, result_str.strip(), status, reason)

    return table
