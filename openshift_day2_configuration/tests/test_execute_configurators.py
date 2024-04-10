from openshift_day2_configuration.configuration.configurations import get_day2_configs
from openshift_day2_configuration.utils.general import base_table, execute_configurators

import pytest


@pytest.fixture
def table():
    yield base_table()


@pytest.fixture
def cofigurators_dict(day2_valid_config):
    _, cofigurators = get_day2_configs(config_file_path=day2_valid_config)
    return cofigurators


def test_execute_configurators_non_valid_configurator(
    no_kubeconfig_env_variable, mocked_client, table, cofigurators_dict
):
    res = execute_configurators(table=table, day2_configurators=cofigurators_dict)
    assert [col.header for col in res.columns] == [
        "Configurator",
        "Step",
        "Status",
        "Failure Reason",
    ]
