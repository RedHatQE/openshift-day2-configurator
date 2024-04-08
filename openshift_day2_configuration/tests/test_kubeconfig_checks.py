import os

import pytest

from openshift_day2_configuration.utils.general import (
    KubeconfigExportedError,
    KubeconfigMissingFileError,
    KubeconfigMissingInConfigError,
    verify_and_set_kubeconfig,
)


@pytest.fixture
def kubeconfig_env_variable():
    os.environ["KUBECONFIG"] = "kubeconfig"
    yield
    del os.environ["KUBECONFIG"]


def test_existing_kubeconfig_env_var(kubeconfig_env_variable):
    with pytest.raises(KubeconfigExportedError):
        verify_and_set_kubeconfig(config={})


def test_missing_kubeconfig_from_config():
    with pytest.raises(KubeconfigMissingInConfigError):
        verify_and_set_kubeconfig(config={})


def test_missing_kubeconfig_file():
    with pytest.raises(KubeconfigMissingFileError):
        verify_and_set_kubeconfig(config={"kubeconfig": "kubeconfig"})
