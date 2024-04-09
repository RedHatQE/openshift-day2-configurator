import os

from pyaml_env.parse_config import yaml
import pytest

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


@pytest.fixture
def day2_config_with_missing_kubeconfig(day2_config_env_variable):
    with open(day2_config_env_variable, "w") as fd:
        fd.write(yaml.dump({"configurators": ["ldap"]}))


@pytest.fixture
def day2_config_with_non_existing_kubeconfig(day2_config_env_variable):
    with open(day2_config_env_variable, "w") as fd:
        fd.write(
            yaml.dump({
                "configurators": ["ldap"],
                "kubeconfig": "non-existing-kubeconfig-path",
            })
        )


@pytest.fixture
def day2_example_config():
    os.environ["OPENSHIFT_DAY2_CONFIG"] = "day2_configuration.example.yaml"


@pytest.fixture
def day2_valid_config(tmp_path):
    day2_config_path = f"{tmp_path}/day2-config.yaml"
    kubeconfig_path = f"{tmp_path}/kubeconfig"
    os.environ["OPENSHIFT_DAY2_CONFIG"] = day2_config_path

    with open(day2_config_path, "w") as fd:
        fd.write(yaml.dump({"configurators": ["ldap"], "kubeconfig": kubeconfig_path}))

    with open(kubeconfig_path, "w") as fd:
        fd.write("apiVersion: v1\nkind: Config")

    yield
    del os.environ["OPENSHIFT_DAY2_CONFIG"]


def test_missing_day2_config_file(day2_config_env_variable):
    with pytest.raises(SystemExit, match="1"):
        from openshift_day2_configuration.utils.general import DAY2_CONFIG  # noqa F401


def test_missing_day2_configurators_in_config(day2_config_with_missing_configurators):
    with pytest.raises(SystemExit, match="2"):
        from openshift_day2_configuration.utils.general import DAY2_CONFIG  # noqa F401


def test_existing_kubeconfig_env_var(day2_example_config, kubeconfig_env_variable):
    with pytest.raises(SystemExit, match="3"):
        from openshift_day2_configuration.utils.general import DAY2_CONFIG  # noqa F401


def test_missing_kubeconfig_path_in_day2_config(day2_config_with_missing_kubeconfig):
    with pytest.raises(SystemExit, match="4"):
        from openshift_day2_configuration.utils.general import DAY2_CONFIG  # noqa F401


def test_not_existing_kubeconfig_path_from_day2_config(
    day2_config_with_non_existing_kubeconfig,
):
    with pytest.raises(SystemExit, match="5"):
        from openshift_day2_configuration.utils.general import DAY2_CONFIG  # noqa F401


def test_day2_config_failed_client(day2_valid_config):
    with pytest.raises(SystemExit, match="6"):
        from openshift_day2_configuration.utils.general import DAY2_CONFIG  # noqa F401
