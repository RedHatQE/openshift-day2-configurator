from __future__ import annotations
import logging
from typing import Any, Dict

from rich import box
from rich.progress import Progress
from rich.table import Table


def verify_and_execute_configurator(
    func: Any,
    config: Dict[str, Any] | None = None,
    logger_obj: logging.Logger | None = None,
    progress: Progress | None = None,
    task_name: str | None = None,
    *args: Any,
    **kwargs: Any,
) -> Dict[str, Dict[str, str | bool]]:
    task_name = f"    {task_name}" if task_name else func.__name__
    task = progress.add_task(task_name, total=1) if progress else None

    try:
        if logger_obj:
            logger_obj.debug(task_name)

        if kwargs and config and (missing_keys := [_key for _key in kwargs if _key != "logger" and _key not in config]):
            if progress and task is not None:
                progress.update(task, advance=1, description=task_name)

            return {task_name: {"res": False, "err": f"Missing config keys: {missing_keys}"}}

        res = func(*args, **kwargs)

        if progress and task is not None:
            progress.update(task, advance=1, description=task_name)

        return res

    except Exception as ex:
        if logger_obj:
            logger_obj.debug(ex)

        if progress and task is not None:
            progress.update(task, advance=1, description=task_name)

        return {task_name: {"res": False, "err": str(ex)}}


def base_table() -> Table:
    table = Table(
        title="Cluster Configuration Report",
        show_lines=True,
        box=box.ROUNDED,
        expand=True,
    )
    table.add_column("Configurator", style="cyan", no_wrap=True)
    table.add_column("Step", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Failure Reason", style="red")

    return table
