import datetime
import logging
import time

import click
from pyaml_env import parse_config
from rich.live import Live
from rich import print
from simple_logger.logger import get_logger

from configurators.ldap import execute_ldap_configuration
from openshift_day2_configuration.utils.general import (
    base_table,
    execute_configurators,
    verify_and_set_kubeconfig,
)

LOGGER = get_logger(name="day2-config-cluster")


@click.command("configurator")
@click.option(
    "--config-file",
    required=True,
    help="Path to day2 configuration.yaml",
    type=click.Path(exists=True),
)
@click.option(
    "--pdb",
    help="Drop to `ipdb` shell on exception",
    is_flag=True,
    show_default=True,
)
@click.option(
    "--non-live-output",
    default=False,
    help="Do not print live output to console as configuration is progressing",
    is_flag=True,
    show_default=True,
    type=click.BOOL,
)
def main(**kwargs):
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
    start_time = time.time()
    should_raise = False
    _logger = get_logger(name="openshift-day2-configuration")
    # TODO: organize logging and time prints
    logging.disable(logging.CRITICAL)

    try:
        main()
    except Exception as ex:
        import sys
        import traceback

        ipdb = __import__("ipdb")  # Bypass debug-statements pre-commit hook

        if "--pdb" in sys.argv:
            extype, value, tb = sys.exc_info()
            traceback.print_exc()
            ipdb.post_mortem(tb)
        else:
            _logger.error(ex)
            should_raise = True
    finally:
        _logger.info(f"Total execution time: {datetime.timedelta(seconds=time.time() - start_time)}")
        if should_raise:
            sys.exit(1)
