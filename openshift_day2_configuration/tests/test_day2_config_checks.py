import os

from pyaml_env.parse_config import yaml
import pytest

from openshift_day2_configuration.configuration.configurations import get_day2_configs

pytestmark = pytest.mark.usefixtures("no_kubeconfig_env_variable")


@pytest.fixture
def no_kubeconfig_env_variable():
    try:
        del os.environ["KUBECONFIG"]
    except KeyError:
        pass


@pytest.fixture
def kubeconfig_env_variable():
    os.environ["KUBECONFIG"] = "kubeconfig"
    yield
    del os.environ["KUBECONFIG"]


@pytest.fixture
def day2_config_env_variable(tmp_path):
    path = f"{tmp_path}/day2-config.yaml"
    os.environ["OPENSHIFT_DAY2_CONFIG"] = path
    yield path
    del os.environ["OPENSHIFT_DAY2_CONFIG"]


@pytest.fixture
def day2_config_with_missing_configurators(day2_config_env_variable):
    with open(day2_config_env_variable, "w") as fd:
        fd.write(yaml.dump({"configurators": []}))

    yield day2_config_env_variable


@pytest.fixture
def day2_config_with_missing_kubeconfig(day2_config_env_variable):
    with open(day2_config_env_variable, "w") as fd:
        fd.write(yaml.dump({"configurators": ["ldap"]}))

    yield day2_config_env_variable


@pytest.fixture
def day2_config_with_non_existing_kubeconfig(day2_config_env_variable):
    with open(day2_config_env_variable, "w") as fd:
        fd.write(
            yaml.dump({
                "configurators": ["ldap"],
                "kubeconfig": "non-existing-kubeconfig-path",
            })
        )

    yield day2_config_env_variable


@pytest.fixture
def day2_example_config():
    config_path = "day2_configuration.example.yaml"
    os.environ["OPENSHIFT_DAY2_CONFIG"] = config_path

    yield config_path


def test_missing_day2_configurators_in_config(day2_config_with_missing_configurators):
    with pytest.raises(SystemExit, match="2"):
        get_day2_configs(config_file_path=day2_config_with_missing_configurators)


def test_existing_kubeconfig_env_var(day2_example_config, kubeconfig_env_variable):
    with pytest.raises(SystemExit, match="3"):
        get_day2_configs(config_file_path=day2_example_config)


def test_missing_kubeconfig_path_in_day2_config(day2_config_with_missing_kubeconfig):
    with pytest.raises(SystemExit, match="4"):
        get_day2_configs(config_file_path=day2_config_with_missing_kubeconfig)


def test_not_existing_kubeconfig_path_from_day2_config(
    day2_config_with_non_existing_kubeconfig,
):
    with pytest.raises(SystemExit, match="5"):
        get_day2_configs(config_file_path=day2_config_with_non_existing_kubeconfig)


def test_day2_config_failed_client(day2_valid_config):
    with pytest.raises(SystemExit, match="6"):
        get_day2_configs(config_file_path=day2_valid_config)


def test_day2_config_success(mocker, day2_valid_config):
    _oc_client = mocker.patch("openshift_day2_configuration.configuration.configurations.get_client")
    _oc_client.resources.api_groups = True
    config, configurators = get_day2_configs(config_file_path=day2_valid_config)
    assert config
    assert configurators
