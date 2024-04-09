import os
import sys
from typing import Dict
from ocp_utilities.infra import get_client
from pyaml_env import parse_config
from simple_logger.logger import get_logger

LOGGER = get_logger("configurations")


def verify_and_set_kubeconfig(config: Dict) -> None:
    if os.environ.get("KUBECONFIG"):
        LOGGER.error("KUBECONFIG environment variable is set. Please unset it.")
        sys.exit(3)

    if not (kubeconfig_path := config.get("kubeconfig")):
        LOGGER.error("Missing kubeconfig in day2 configuration yaml")
        sys.exit(4)

    if not os.path.exists(kubeconfig_path):
        LOGGER.error(f"Kubeconfig {kubeconfig_path} does not exist")
        sys.exit(5)

    os.environ["KUBECONFIG"] = kubeconfig_path

    try:
        get_client().resources.api_groups

    except Exception as ex:
        LOGGER.error(f"Cannot access cluster with kubeconfig {kubeconfig_path}")
        LOGGER.debug(ex, exc_info=True)
        sys.exit(6)


def get_day2_configs():
    day2_config = os.getenv(
        "OPENSHIFT_DAY2_CONFIG",
        os.path.expanduser("~/.config/openshift-day2/config.yaml"),
    )

    if not os.path.exists(day2_config):
        LOGGER.error(f"Openshift Day2 config {day2_config} file does not exist")
        sys.exit(1)

    day2_config = parse_config(day2_config)

    if not (day2_configurators := day2_config.get("configurators")):
        LOGGER.error("Missing configurators in day2 configuration yaml")
        sys.exit(2)

    verify_and_set_kubeconfig(config=day2_config)

    return day2_config, day2_configurators
