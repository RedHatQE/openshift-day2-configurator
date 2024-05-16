from typing import Any

import pytest
from ocp_resources.resource import Resource
from simple_logger.logger import get_logger

from openshift_day2_configurator.utils.resources import create_ocp_resource


LOGGER = get_logger(name="test-resources")


class MockedResource(Resource):
    api_group = "test-api-group"
    api_version = "test-api-version"

    def __init__(self, raise_ex: bool = False, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.raise_ex = raise_ex

    def exists(self) -> None:
        pass

    def deploy(self, wait=False) -> None:
        if self.raise_ex:
            raise Exception("MockedResource deploy failed")


@pytest.fixture
def mocked_resource(mocked_client):
    return MockedResource(name="test-resource", client=mocked_client)


def test_create_new_resource(mocked_resource):
    mocked_resource.exists = False
    assert create_ocp_resource(ocp_resource=mocked_resource, logger=LOGGER) == {
        "res": True,
        "err": "",
    }


def test_create_existing_resource(mocked_resource):
    mocked_resource.exists = True
    assert create_ocp_resource(ocp_resource=mocked_resource, logger=LOGGER) == {
        "res": False,
        "err": "MockedResource test-resource already exists",
    }


def test_failed_create_resource(mocked_resource):
    mocked_resource.exists = False
    mocked_resource.raise_ex = True
    assert create_ocp_resource(ocp_resource=mocked_resource, logger=LOGGER) == {
        "res": False,
        "err": "MockedResource deploy failed",
    }
