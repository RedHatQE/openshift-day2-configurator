import logging
from openshift_day2_configurator.configuration.configurations import get_day2_configs
from openshift_day2_configurator.configurators.executor import execute_configurators
from openshift_day2_configurator.utils.general import base_table

import pytest


@pytest.fixture
def table():
    yield base_table()


@pytest.fixture
def day2_configurators(valid_setup):
    _, day2_configurators = get_day2_configs(config_file=valid_setup)
    yield day2_configurators


def test_execute_configurators_non_valid_configurator(day2_configurators, table):
    res = execute_configurators(
        day2_configurators=day2_configurators,
        table=table,
        logger=logging.getLogger(name="test-execute-configurators"),
    )
    assert [col.header for col in res.columns] == [
        "Configurator",
        "Step",
        "Status",
        "Failure Reason",
    ]
