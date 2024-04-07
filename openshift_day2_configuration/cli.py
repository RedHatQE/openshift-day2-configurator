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
def main(**kwargs):
    configurators_mapping = {"ldap": execute_ldap_configuration}
    config_results = {}

    day2_config = parse_config(kwargs["config_file"])
    verify_and_set_kubeconfig(config=day2_config)

    if not (day2_configurators := day2_config.get("configurators")):
        raise ValueError("Missing configurators in day2_configuration.yaml")

    table = base_table()
    failed_str = "[red]Failed[not red]"

    with Live(table, refresh_per_second=10):
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
