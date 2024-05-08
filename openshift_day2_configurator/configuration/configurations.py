import os
import sys
from typing import Any, Dict, Tuple

from kubernetes.dynamic import DynamicClient
from ocp_utilities.infra import get_client
from pyaml_env import parse_config
import rich


PRINT_ERROR_PREFIX: str = "[red]ERROR:[not red]"


def get_day2_configs(config_file: str) -> Tuple[Dict[str, Any], Dict[str, Any], DynamicClient]:
    day2_config = parse_config(config_file)

    if not (day2_configurators := day2_config.get("configurators")):
        rich.print(f"{PRINT_ERROR_PREFIX} Missing configurators in day2 configuration yaml")
        sys.exit(2)

    client = verify_and_set_kubeconfig_and_client(config=day2_config)

    return day2_config, day2_configurators, client


def verify_and_set_kubeconfig_and_client(config: Dict[str, Any]) -> DynamicClient:
    if os.environ.get("KUBECONFIG"):
        rich.print(f"{PRINT_ERROR_PREFIX} KUBECONFIG environment variable is set. Please unset it.")
        sys.exit(3)

    if not (kubeconfig_path := config.get("kubeconfig")):
        rich.print(f"{PRINT_ERROR_PREFIX} Missing kubeconfig in day2 configuration yaml")
        sys.exit(4)

    if not os.path.exists(kubeconfig_path):
        rich.print(f"{PRINT_ERROR_PREFIX} Kubeconfig {kubeconfig_path} does not exist")
        sys.exit(5)

    os.environ["KUBECONFIG"] = kubeconfig_path

    try:
        client = get_client(config_file=kubeconfig_path)
        _ = client.resources.api_groups
        return client

    except Exception as ex:
        rich.print(f"{PRINT_ERROR_PREFIX} Cannot access cluster with kubeconfig {kubeconfig_path}")
        rich.print(ex)
        sys.exit(6)
