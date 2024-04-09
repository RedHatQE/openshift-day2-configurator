import click
from pyhelper_utils.runners import function_runner_with_pdb
from rich import print
from rich.progress import Progress


from openshift_day2_configuration.configuration.configurations import get_day2_configs
from openshift_day2_configuration.utils.general import (
    base_table,
    execute_configurators,
    set_logger,
)

LOGGER = set_logger(name="day2-config-cluster")


@click.command("configurator")
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
def main(pdb):
    table = base_table()
    execute_configurators_kwargs = {
        "table": table,
    }
    day2_config, day2_configurators = get_day2_configs()

    if pdb:
        table = execute_configurators(**execute_configurators_kwargs)
    else:
        with Progress() as progress:
            task_progress = 1
            task = progress.add_task(
                "[green]Executing Day2 configurations ",
                total=len(day2_configurators) + task_progress,
            )
            table = execute_configurators(
                progress=progress,
                task=task,
                task_progress=task_progress,
                **execute_configurators_kwargs,
            )

    print(table)

    if output_file := day2_config.get("output_log_file"):
        with open(output_file, "w") as output_file:
            print(table, file=output_file)


if __name__ == "__main__":
    function_runner_with_pdb(func=main)
