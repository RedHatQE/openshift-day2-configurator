from openshift_day2_configuration.utils.general import base_table, execute_configurators

import pytest


@pytest.fixture
def table():
    yield base_table()


def test_execute_configurators_non_valid_configurator(
    day2_valid_config, no_kubeconfig_env_variable, mocked_client, table
):
    res = execute_configurators(table=table)
    assert [col.header for col in res.columns] == [
        "Configurator",
        "Step",
        "Status",
        "Failure Reason",
    ]
