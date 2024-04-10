import os
import sys
from typing import Dict, Tuple
from ocp_utilities.infra import get_client
from pyaml_env import parse_config
import rich


def get_day2_configs(config_file: str) -> Tuple[Dict, Dict]:
    if not config_file or not os.path.exists(config_file):
        rich.print(f"Openshift Day2 config {config_file} file does not exist")
        sys.exit(1)

    day2_config = parse_config(config_file)

    if not (day2_configurators := day2_config.get("configurators")):
        rich.print("Missing configurators in day2 configuration yaml")
        sys.exit(2)

    verify_and_set_kubeconfig(config=day2_config)

    return day2_config, day2_configurators


def verify_and_set_kubeconfig(config: Dict) -> None:
    if os.environ.get("KUBECONFIG"):
        rich.print("KUBECONFIG environment variable is set. Please unset it.")
        sys.exit(3)

    if not (kubeconfig_path := config.get("kubeconfig")):
        rich.print("Missing kubeconfig in day2 configuration yaml")
        sys.exit(4)

    if not os.path.exists(kubeconfig_path):
        rich.print(f"Kubeconfig {kubeconfig_path} does not exist")
        sys.exit(5)

    os.environ["KUBECONFIG"] = kubeconfig_path

    try:
        get_client().resources.api_groups

    except Exception as ex:
        rich.print(f"Cannot access cluster with kubeconfig {kubeconfig_path}")
        rich.print(ex)
        sys.exit(6)
