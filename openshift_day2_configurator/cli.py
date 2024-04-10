import logging
import os
import click
from pyhelper_utils.runners import function_runner_with_pdb
from rich import print
from rich.progress import Progress
from simple_logger.logger import get_logger


from openshift_day2_configurator.configuration.configurations import get_day2_configs
from openshift_day2_configurator.utils.general import (
    base_table,
    execute_configurators,
)


def openshift_day2_configurator_executor(config_file: str, pdb: bool, verbose: bool) -> None:
    logger = get_logger(name="openshift-day2-configurator")

    if verbose:
        logger.setLevel("DEBUG")
    else:
        logging.disable(logging.INFO)

    _base_table = base_table()
    day2_config, day2_configurators = get_day2_configs(config_file=config_file)

    if pdb or verbose:
        table = execute_configurators(day2_configurators=day2_configurators, table=_base_table, logger=logger)
    else:
        with Progress() as progress:
            task_progress = 1
            task = progress.add_task(
                "[green]Executing Day2 configurations ",
                total=len(day2_configurators) + task_progress,
            )
            table = execute_configurators(
                day2_configurators=day2_configurators,
                table=_base_table,
                progress=progress,
                task=task,
                task_progress=task_progress,
                logger=logger,
            )

    print(table)

    if output_file := day2_config.get("output_log_file"):
        with open(output_file, "w") as output_file:
            print(table, file=output_file)


@click.command("openshift-day2-configurator")
@click.option(
    "-c",
    "--config-file",
    default=os.environ.get("OPENSHIFT_DAY2_CONFIG"),
    type=click.Path(exists=True, resolve_path=True),
    show_default=True,
    help="openshift day2 configurator config file",
)
@click.option(
    "--pdb",
    is_flag=True,
    show_default=True,
    help="Drop to `ipdb` shell on exception",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    show_default=True,
    help="Enable debug logging, if not set no logs will be printed",
)
def cli_entrypoint(config_file: str, pdb: bool, verbose: bool) -> None:
    openshift_day2_configurator_executor(config_file=config_file, pdb=pdb, verbose=verbose)


if __name__ == "__main__":
    function_runner_with_pdb(func=cli_entrypoint)
