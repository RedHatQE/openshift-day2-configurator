from __future__ import annotations
import logging
from typing import Any, Dict, Union, Optional

import base64
from rich import box
from rich.progress import Progress, TaskID
from rich.table import Table


def verify_and_execute_configurator_task(
    func: Any,
    config: Optional[Dict[str, Any]] = None,
    logger_obj: Optional[logging.Logger] = None,
    progress: Optional[Progress] = None,
    task_name: Optional[str] = None,
    *args: Any,
    **kwargs: Any,
) -> Dict[str, Dict[str, Union[str, bool]]]:
    task_name = f"    {task_name}" if task_name else func.__name__
    task = progress.add_task(task_name, total=1) if progress else None

    try:
        if logger_obj:
            logger_obj.debug(task_name)

        if (
            kwargs
            and config
            and (missing_keys := [_key for _key in kwargs if _key not in ("logger", "client") and _key not in config])
        ):
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


def str_b64encode(str_to_encode: str) -> str:
    utf8_str = "utf-8"
    return base64.b64encode(str_to_encode.encode(utf8_str)).decode(utf8_str)


def execute_configurator(
    verify_and_execute_kwargs: Dict[str, Any],
    tasks_dict: Dict[str, Dict[str, Any]],
    description: str,
) -> Dict[str, Dict[str, Union[str, bool]]]:
    status_dict = {}
    task_id: Optional[TaskID] = None

    if progress := verify_and_execute_kwargs["progress"]:
        task_id = progress.add_task(description=f"  {description}", total=len(tasks_dict))

    for _task, _func_config in tasks_dict.items():
        _kwargs: Dict[str, Any] = {**verify_and_execute_kwargs, **_func_config["func_kwargs"]}
        status_dict.update(verify_and_execute_configurator_task(func=_func_config["func"], task_name=_task, **_kwargs))

        if progress and task_id is not None:
            progress.update(task_id, advance=1)

    if progress and task_id is not None:
        progress.update(task_id, advance=1)

    return status_dict
