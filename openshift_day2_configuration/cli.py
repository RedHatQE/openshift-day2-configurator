import logging

import click
from pyaml_env import parse_config
from pyhelper_utils.runners import function_runner_with_pdb
from rich.live import Live
from rich import print
from simple_logger.logger import get_logger

from configurators.ldap import execute_ldap_configuration
from openshift_day2_configuration.utils.general import (
    base_table,
    execute_configurators,
    verify_and_set_kubeconfig,
)

LOGGER = get_logger(name="day2-config-cluster", level=logging.NOTSET)


@click.command("configurator")
@click.option(
    "--config-file",
    required=True,
    type=click.Path(exists=True),
    help="Path to day2 configuration.yaml",
)
@click.option(
    "--pdb",
    is_flag=True,
    show_default=True,
    help="Drop to `ipdb` shell on exception",
)
@click.option(
    "--non-live-output",
    default=False,
    is_flag=True,
    show_default=True,
    type=click.BOOL,
    help="""\b
Do not print live output to console as configuration is progressing""",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], case_sensitive=False),
    help="""\b
Sets log level; if not passed, logs will be silenced
""",
)
def main(**kwargs):
    if log_level := kwargs.get("log_level"):
        LOGGER.setLevel(log_level)

    configurators_mapping = {"ldap": execute_ldap_configuration}

    day2_config = parse_config(kwargs["config_file"])
    verify_and_set_kubeconfig(config=day2_config)

    if not (day2_configurators := day2_config.get("configurators")):
        raise ValueError("Missing configurators in day2_configuration.yaml")

    table = base_table()

    if kwargs.get("non_live_output"):
        table = execute_configurators(
            configurators_mapping=configurators_mapping,
            day2_configurators=day2_configurators,
            table=table,
        )

        print(table)

    else:
        with Live(table, refresh_per_second=10):
            table = execute_configurators(
                configurators_mapping=configurators_mapping,
                day2_configurators=day2_configurators,
                table=table,
            )

    if output_file := day2_config.get("output_log_file"):
        with open(output_file, "w") as output_file:
            print(table, file=output_file)


if __name__ == "__main__":
    function_runner_with_pdb(func=main)
