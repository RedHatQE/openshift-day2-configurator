import logging
from typing import Callable, Dict, Optional

from pyhelper_utils.runners import sys
from rich import box
from rich.progress import Progress, TaskID
from rich.table import Table

from openshift_day2_configurator.configurators.mappings import configurators_mappings


def verify_and_execute_configurator(
    func: Callable,
    config: Optional[Dict] = None,
    logger_obj: Optional[logging.Logger] = None,
    *args,
    **kwargs,
) -> Dict:
    try:
        if kwargs and config and (missing_keys := [_key for _key in kwargs if _key not in config]):
            return {"res": False, "err": f"Missing config keys: {missing_keys}"}

        return func(*args, **kwargs)
    except Exception as ex:
        if logger_obj:
            logger_obj.info(ex)
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
    task: Optional[TaskID] = None,
    task_progress: Optional[int] = None,
) -> Table:
    failed_str = "[red]Failed[not red]"
    _configurators_mappings = configurators_mappings()

    for configurator_name, config in day2_configurators.items():
        if configurator_name not in _configurators_mappings:
            table.add_row(
                configurator_name,
                "",
                failed_str,
                "Missing configurator in configuration mapping",
            )
            continue

        for result_str, result_status in _configurators_mappings[configurator_name](config=config).items():
            if progress:
                if not task:
                    logger.debug("task not set")
                    sys.exit(1)

                progress.update(task, advance=task_progress, refresh=True)

            status = "Passed" if result_status["res"] else failed_str
            reason = "" if result_status["res"] else result_status["err"]
            table.add_row(configurator_name, result_str, status, reason)

    return table