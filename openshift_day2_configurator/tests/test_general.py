from pyaml_env import parse_config
import os
from openshift_day2_configurator.cli import openshift_day2_configurator_executor
from openshift_day2_configurator.utils.general import base_table


def test_base_table():
    table = base_table()
    assert [col.header for col in table.columns] == [
        "Configurator",
        "Step",
        "Status",
        "Failure Reason",
    ]


def test_output_log_file(valid_setup):
    openshift_day2_configurator_executor(config_file=valid_setup, pdb=False, verbose=True)
    assert os.path.exists(parse_config(valid_setup).get("output_log_file"))
