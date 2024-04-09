import os

import pytest


@pytest.fixture
def kubeconfig_env_variable():
    os.environ["KUBECONFIG"] = "kubeconfig"
    yield
    del os.environ["KUBECONFIG"]


@pytest.fixture
def day2_config_env_variable(tmp_path):
    path = f"{tmp_path}/kubeconfig"
    os.environ["OPENSHIFT_DAY2_CONFIG"] = path
    yield path
    del os.environ["OPENSHIFT_DAY2_CONFIG"]


def test_missing_day2_config_file(day2_config_env_variable):
    with pytest.raises(SystemExit, match="1"):
        from openshift_day2_configuration.utils.general import DAY2_CONFIG  # noqa F401


def test_existing_kubeconfig_env_var(kubeconfig_env_variable):
    with pytest.raises(SystemExit, match="2"):
        from openshift_day2_configuration.utils.general import DAY2_CONFIG  # noqa F401


#     with pytest.raises(SystemExit, match="KUBECONFIG environment variable is set. Please unset it."):
#         verify_and_set_kubeconfig(config={})
#
#
# def test_missing_kubeconfig_from_config():
#     with pytest.raises(SystemExit, match="Missing kubeconfig in day2 configuration yaml."):
#         verify_and_set_kubeconfig(config={})
#
#
# def test_missing_kubeconfig_file():
#     with pytest.raises(SystemExit, match="Kubeconfig kubeconfig does not exist."):
#         verify_and_set_kubeconfig(config={"kubeconfig": "kubeconfig"})
