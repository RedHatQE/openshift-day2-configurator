import os
import sys
from functools import wraps
from typing import Any, Dict, List, Optional

from ocp_utilities.infra import get_client
from pyaml_env import parse_config
from rich import box
from rich.progress import Progress, TaskID
from rich.table import Table
from simple_logger.logger import get_logger


LOGGER = get_logger(__name__)


class KubeconfigExportedError(Exception):
    pass


class KubeconfigMissingInConfigError(Exception):
    pass


class KubeconfigMissingFileError(Exception):
    pass


def verify_and_set_kubeconfig(config: Dict) -> None:
    if os.environ.get("KUBECONFIG"):
        LOGGER.error("KUBECONFIG environment variable is set. Please unset it.")
        sys.exit(1)

    if not (kubeconfig_path := config.get("kubeconfig")):
        LOGGER.error("Missing kubeconfig in day2 configuration yaml")
        sys.exit(1)

    if not os.path.exists(kubeconfig_path):
        LOGGER.error(f"Kubeconfig {kubeconfig_path} does not exist")
        sys.exit(1)

    os.environ["KUBECONFIG"] = kubeconfig_path

    try:
        get_client()

    except Exception as ex:
        LOGGER.error(f"Cannot access cluster with kubeconfig {kubeconfig_path}, {ex}")
        sys.exit(1)


def get_day2_configs():
    day2_config = os.getenv("OPENSHIFT_DAY2_CONFIG", os.path.expanduser("~/.config/openshift-day2/config.yaml"))

    if not os.path.exists(day2_config):
        LOGGER.error(f"Openshift Day2 config {day2_config} file does not exist")
        sys.exit(1)

    day2_config = parse_config(day2_config)

    if not (day2_configurators := day2_config.get("configurators")):
        LOGGER.error("Missing configurators in day2 configuration yaml")
        sys.exit(1)

    verify_and_set_kubeconfig(config=day2_config)

    return day2_config, day2_configurators


DAY2_CONFIG, DAY2_CONFIGURATORS = get_day2_configs()


def verify_and_execute_configurator(
    config: Optional[Dict] = None,
    config_keys: Optional[List] = None,
    logger: Optional[LOGGER] = None,
) -> Any:
    """
    Decorator to verify and execute configurator.

    Args:
        config (Dict): configuration dict.
        config_keys (List): list of keys that should be in the config.
        logger (Logger): logger to use, if not passed, logs will not be displayed.

    Returns:
        Any: the underline function return value.
    """

    def wrapper(func):
        @wraps(func)
        def inner(*args, **kwargs):
            try:
                if config_keys and (missing_keys := [_key for _key in config_keys if _key not in config]):
                    return {"res": False, "err": f"Missing config keys: {missing_keys}"}

                return func(*args, **kwargs)
            except Exception as ex:
                if logger:
                    logger.info(ex)
                return {"res": False, "err": str(ex)}

        return inner

    return wrapper


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
    configurators_mapping: Dict,
    table: Table,
    progress: Optional[Progress] = None,
    task: Optional[TaskID] = None,
    task_progress: Optional[int] = None,
) -> Table:
    failed_str = "[red]Failed[not red]"

    for configurator_name, config in DAY2_CONFIGURATORS.items():
        if configurator_name not in configurators_mapping:
            table.add_row(
                configurator_name,
                "",
                failed_str,
                "Missing configurator in configuration mapping",
            )
            continue

        for result_str, result_status in configurators_mapping[configurator_name](config=config).items():
            if progress:
                progress.update(task, advance=task_progress, refresh=True)

            status = "Passed" if result_status["res"] else failed_str
            reason = "" if result_status["res"] else result_status["err"]
            table.add_row(configurator_name, result_str, status, reason)

    return table
