import os
from functools import wraps
from typing import Any, Dict, List, Optional
from logging import Logger

from rich import box
from rich.table import Table


class KubeconfigExportedError(Exception):
    pass


class KubeconfigMissingInConfigError(Exception):
    pass


class KubeconfigMissingFileError(Exception):
    pass


def verify_and_execute_configurator(
    config_keys: Optional[List] = None,
    logger: Optional[Logger] = None,
) -> Any:
    """
    Decorator to verify and execute configurator.

    Configuration is verified by checking if all required keys are in the config.
    Configuration dict is set as `config` class attribute in the underline function.

    Example:
        @verify_and_execute_configurator(config_keys=["bind_password"], logger=LOGGER)

    Args:
        config_keys (List): list of keys that should be in the config.
        logger (Logger): logger to use, if not passed, logs will not be displayed.

    Returns:
        Any: the underline function return value.
    """

    def wrapper(func):
        @wraps(func)
        def inner(*args, **kwargs):
            try:
                if config_keys and (missing_keys := [_key for _key in config_keys if _key not in args[0].config]):
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
    table.add_column("Configuration", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Failure Reason", style="red")

    return table


def verify_and_set_kubeconfig(config: Dict) -> None:
    if os.environ.get("KUBECONFIG"):
        raise KubeconfigExportedError("KUBECONFIG environment variable is set. Please unset it.")

    if not (kubeconfig_path := config.get("kubeconfig")):
        raise KubeconfigMissingInConfigError("Missing kubeconfig in day2_configuration.yaml")

    if not os.path.exists(kubeconfig_path):
        raise KubeconfigMissingFileError(f"Kubeconfig {kubeconfig_path} does not exist")

    os.environ["KUBECONFIG"] = kubeconfig_path


def execute_configurators(configurators_mapping: Dict, day2_configurators: Dict, table: Table) -> Table:
    config_results = {}
    failed_str = "[red]Failed[not red]"

    for configurator_name, config in day2_configurators.items():
        if configurator_name not in configurators_mapping:
            config_results.setdefault("missing_configurators", []).append(configurator_name)
            table.add_row(
                configurator_name,
                "",
                failed_str,
                "Missing configurator in configuration mapping",
            )
            continue

        config_results[configurator_name] = config_results = configurators_mapping[configurator_name](config=config)

        for result_str, result_status in config_results.items():
            status = "Passed" if result_status["res"] else failed_str
            reason = "" if result_status["res"] else result_status["err"]
            table.add_row(configurator_name, result_str, status, reason)

    return table
