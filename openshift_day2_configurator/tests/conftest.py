import os
import yaml
import pytest


@pytest.fixture
def day2_valid_config(tmp_path):
    day2_config_path = f"{tmp_path}/day2-config.yaml"
    kubeconfig_path = f"{tmp_path}/kubeconfig"
    output_file_path = f"{tmp_path}/output.txt"
    os.environ["OPENSHIFT_DAY2_CONFIG"] = day2_config_path

    with open(day2_config_path, "w") as fd:
        fd.write(
            yaml.dump({
                "configurators": {"configurator": "exec_configurator"},
                "kubeconfig": kubeconfig_path,
                "output_log_file": output_file_path,
            })
        )

    with open(kubeconfig_path, "w") as fd:
        fd.write("apiVersion: v1\nkind: Config")

    yield day2_config_path
    del os.environ["OPENSHIFT_DAY2_CONFIG"]


@pytest.fixture
def no_kubeconfig_env_variable():
    try:
        del os.environ["KUBECONFIG"]
    except KeyError:
        pass


@pytest.fixture
def mocked_client(mocker):
    _oc_client = mocker.patch("openshift_day2_configurator.configuration.configurations.get_client")
    _oc_client.resources.api_groups = True

    return _oc_client


@pytest.fixture
def valid_setup(day2_valid_config, no_kubeconfig_env_variable, mocked_client):
    yield day2_valid_config
