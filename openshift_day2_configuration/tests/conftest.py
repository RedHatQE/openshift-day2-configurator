import os
import yaml
import pytest


@pytest.fixture
def day2_valid_config(tmp_path):
    day2_config_path = f"{tmp_path}/day2-config.yaml"
    kubeconfig_path = f"{tmp_path}/kubeconfig"
    os.environ["OPENSHIFT_DAY2_CONFIG"] = day2_config_path

    with open(day2_config_path, "w") as fd:
        fd.write(
            yaml.dump({
                "configurators": {"configurator": "exec_configurator"},
                "kubeconfig": kubeconfig_path,
            })
        )

    with open(kubeconfig_path, "w") as fd:
        fd.write("apiVersion: v1\nkind: Config")

    yield
    del os.environ["OPENSHIFT_DAY2_CONFIG"]


@pytest.fixture
def no_kubeconfig_env_variable():
    try:
        del os.environ["KUBECONFIG"]
    except KeyError:
        pass


@pytest.fixture
def mocked_client(mocker):
    _oc_client = mocker.patch("openshift_day2_configuration.configuration.configurations.get_client")
    _oc_client.resources.api_groups = True
