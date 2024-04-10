import logging
from typing import Callable, Dict, Optional

from rich import box
from rich.progress import Progress
from rich.table import Table

from openshift_day2_configurator.configurators.mappings import configurators_mappings


def verify_and_execute_configurator(
    func: Callable,
    config: Optional[Dict] = None,
    logger_obj: Optional[logging.Logger] = None,
    progress: Optional[Progress] = None,
    task_name: Optional[str] = None,
    *args,
    **kwargs,
) -> Dict:
    task_name = f"    {task_name}" if task_name else func.__name__
    task = progress.add_task(task_name, total=1) if progress else None

    try:
        if logger_obj:
            logger_obj.debug(task_name)

        if kwargs and config and (missing_keys := [_key for _key in kwargs if _key not in config]):
            if progress and task is not None:
                progress.update(task, advance=1, description=task_name)

            return {"res": False, "err": f"Missing config keys: {missing_keys}"}

        res = func(*args, **kwargs)

        if progress and task is not None:
            progress.update(task, advance=1, description=task_name)

        return res

    except Exception as ex:
        if logger_obj:
            logger_obj.debug(ex)

        if progress and task is not None:
            progress.update(task, advance=1, description=task_name)

        return {"res": False, "err": str(ex)}


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


def execute_configurators(
    day2_configurators: Dict,
    table: Table,
    logger: logging.Logger,
    progress: Optional[Progress] = None,
    task_progress: Optional[int] = None,
) -> Table:
    failed_str = "[red]Failed[not red]"
    _configurators_mappings = configurators_mappings()

    task = None
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
                "",
                failed_str,
                "Missing configurator mapping in configuration file",
            )
            continue

        for result_str, result_status in _configurators_mappings[configurator_name](
            config=config, logger=logger, progress=progress
        ).items():
            if progress and task is not None:
                progress.update(task, advance=task_progress, refresh=True)

            status = "Passed" if result_status["res"] else failed_str
            reason = "" if result_status["res"] else result_status["err"]
            table.add_row(configurator_name, result_str, status, reason)

    return table
