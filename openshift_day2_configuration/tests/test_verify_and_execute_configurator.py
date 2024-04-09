import pytest
from simple_logger.logger import get_logger

from openshift_day2_configuration.utils.general import verify_and_execute_configurator

LOGGER = get_logger(name="test-configurator")


@pytest.fixture
def function_returns():
    def foo():
        pass

    yield foo


@pytest.fixture
def function_raises():
    def foo():
        raise ValueError

    yield foo


def test_missing_keys_from_config(function_returns):
    output = verify_and_execute_configurator(
        func=function_returns,
        config={"key2": "value2"},
        logger_obj=LOGGER,
        key1="key1",
    )
    assert output["res"] is False
    assert output["err"] == "Missing config keys: ['key1']"


def test_function_raises_exception(function_raises):
    output = verify_and_execute_configurator(func=function_raises)
    assert output["res"] is False
    assert not output["err"]
