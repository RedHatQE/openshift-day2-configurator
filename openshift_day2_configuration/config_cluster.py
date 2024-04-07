import os

from rich import box
from rich.live import Live
from rich.table import Table
from rich import print
from simple_logger.logger import get_logger

from configurators.ldap import execute_ldap_configuration
from openshift_day2_configuration.utils.general import DAY2_CONFIG, DAY2_CONFIGURATORS

CONFIGURATORS_MAPPING = {"ldap": execute_ldap_configuration}
LOGGER = get_logger(name="day2-config-cluster")


class KubeconfigExportedError(Exception):
    pass


class KubeconfigMissingInConfigError(Exception):
    pass


def main():
    config_results = {}

    if os.environ.get("KUBECONFIG"):
        raise KubeconfigExportedError("KUBECONFIG environment variable is set. Please unset it.")

    if not (kubeconfig_path := DAY2_CONFIG.get("kubeconfig")):
        raise KubeconfigMissingInConfigError("Missing kubeconfig in day2_configuration.yaml")

    os.environ["KUBECONFIG"] = kubeconfig_path

    if not DAY2_CONFIGURATORS:
        raise ValueError("Missing configurators in day2_configuration.yaml")

    table = base_table()
    with Live(table):
        for configurator_name, config in DAY2_CONFIGURATORS.items():
            if configurator_name not in CONFIGURATORS_MAPPING:
                DAY2_CONFIG.setdefault("missing_configurators", []).append(configurator_name)
                continue

            config_results[configurator_name] = CONFIGURATORS_MAPPING[configurator_name]()

            for result_str, result_status in config_results[configurator_name].items():
                status = "Passed" if result_status["res"] else "[red]Failed[not red]"
                reason = "" if result_status["res"] else result_status["err"]
                table.add_row(configurator_name, result_str, status, reason)

    if output_file := DAY2_CONFIG.get("output_log_file"):
        with open(output_file, "w") as output_file:
            print(table, file=output_file)


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


if __name__ == "__main__":
    import logging

    logging.disable(logging.CRITICAL)

    LOGGER.info("Configuring cluster")
    LOGGER.debug("Configuring cluster 1")
    main()
