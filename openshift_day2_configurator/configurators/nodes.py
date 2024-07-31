import shlex
import logging
from timeout_sampler import TimeoutSampler
from pyhelper_utils.shell import run_command
from typing import Any, Dict, Union, Optional, List, Tuple, Callable

from openshift_day2_configurator.utils.general import (
    execute_configurator,
    str_b64encode,
)
from rich.progress import Progress
from openshift_day2_configurator.utils.resources import create_ocp_resource
from kubernetes.dynamic import DynamicClient
from ocp_resources.machine_config import MachineConfig
from ocp_resources.node import Node

MACHINE_CONFIGURATION_ROLE_LABEL: str = "machineconfiguration.openshift.io/role"
MASTER_NODE_TYPE: str = "master"
WORKER_NODE_TYPE: str = "worker"
TIMEOUT_30MIN: int = 30 * 60


def configure_chrony_ntp_on_nodes_message(nodes_type: str) -> str:
    return f"Configure Chrony NTP on {nodes_type} nodes"


def adding_kernel_arguments_to_nodes_message(nodes_type: str) -> str:
    return f"Adding kernel arguments to {nodes_type} nodes"


def adding_realtime_kernel_to_nodes_message(nodes_type: str) -> str:
    return f"Adding real-time kernel to {nodes_type} nodes"


def configure_journald_setting_on_nodes_message(nodes_type: str) -> str:
    return f"Configure journald settings on {nodes_type} nodes"


def configure_image_registry_setting_on_nodes_message(nodes_type: str) -> str:
    return f"Configure image registry settings on {nodes_type} nodes"


def adding_extensions_to_rhcos_on_nodes_message(nodes_type: str) -> str:
    return f"Adding extensions to RHCOS on {nodes_type} nodes"


def get_node_role(node: Node) -> str:
    labels = node.instance.to_dict().get("metadata", {}).get("labels", {})
    node_role_kubernetes_io = "node-role.kubernetes.io"

    if f"{node_role_kubernetes_io}/master" in labels or f"{node_role_kubernetes_io}/control-plane" in labels:
        return MASTER_NODE_TYPE
    return WORKER_NODE_TYPE


def get_cluster_nodes(client: DynamicClient, node_role: str) -> List[Node]:
    return [node for node in Node.get(dyn_client=client) if get_node_role(node=node) == node_role]


def get_test_node_name(client: DynamicClient, nodes_type: str) -> str:
    return get_cluster_nodes(client=client, node_role=nodes_type)[0].name


def oc_debug_node_with_command(node_name: str, command: str) -> Tuple[bool, str, str]:
    cmd: List[str] = shlex.split(f"oc debug node/{node_name} -- {command}")
    return run_command(command=cmd, check=False, verify_stderr=False)


def wait_for_node_condition(
    timeout: int,
    node_name: str,
    node_command: str,
    condition_met: Callable[[str], bool],
) -> None:
    for node_command_res, node_command_out, node_command_err in TimeoutSampler(
        wait_timeout=timeout,
        sleep=10,
        func=oc_debug_node_with_command,
        node_name=node_name,
        command=node_command,
    ):
        if condition_met(node_command_out):
            break


def configure_chrony_ntp_on_nodes(
    client: DynamicClient,
    logger: logging.Logger,
    cluster_domain: str,
    nodes_type: str,
) -> Dict[str, Dict[str, str]]:
    logger.debug(configure_chrony_ntp_on_nodes_message(nodes_type=nodes_type))

    chrony_conf = f"""
    pool ntp.{cluster_domain} iburst driftfile /var/lib/chrony/drift makestep 1.0 3
    rtcsync
    logdir /var/log/chrony
    """

    return {
        configure_chrony_ntp_on_nodes_message(nodes_type=nodes_type): create_ocp_resource(
            ocp_resource=MachineConfig(
                client=client,
                name=f"99-{nodes_type}s-chrony-configuration",
                label={MACHINE_CONFIGURATION_ROLE_LABEL: nodes_type},
                config={
                    "ignition": {
                        "config": {},
                        "security": {"tls": {}},
                        "timeouts": {},
                        "version": "3.1.0",
                        "networkd": {},
                        "passwd": {},
                        "storage": {
                            "files": [
                                {
                                    "contents": {
                                        "source": f"data:text/plain;charset=utf-8;base64,{str_b64encode(str_to_encode=chrony_conf)}"
                                    },
                                    "mode": 420,
                                    "overwrite": True,
                                    "path": "/etc/chrony.conf",
                                }
                            ]
                        },
                    }
                },
            ),
            logger=logger,
        )
    }


def adding_kernel_arguments_to_nodes(
    client: DynamicClient,
    logger: logging.Logger,
    nodes_type: str,
) -> Dict[str, Dict[str, Union[str, bool]]]:
    def is_new_kernel_argument_added(kernel_args: str) -> bool:
        return new_kernel_argument in kernel_args

    logger.debug(adding_kernel_arguments_to_nodes_message(nodes_type=nodes_type))

    new_kernel_argument = "enforcing=0"

    kernel_argument_task_dict = {
        adding_kernel_arguments_to_nodes_message(nodes_type=nodes_type): create_ocp_resource(
            ocp_resource=MachineConfig(
                client=client,
                name=f"05-{nodes_type}-kernelarg-selinuxpermissive",
                label={MACHINE_CONFIGURATION_ROLE_LABEL: nodes_type},
                config={
                    "ignition": {
                        "version": "3.1.0",
                        "kernelArguments": [new_kernel_argument],
                    }
                },
            ),
            logger=logger,
        )
    }

    test_node_name = get_test_node_name(client=client, nodes_type=nodes_type)
    try:
        wait_for_node_condition(
            timeout=TIMEOUT_30MIN,
            node_name=test_node_name,
            node_command="cat /host/proc/cmdline",
            condition_met=is_new_kernel_argument_added,
        )
    except Exception as ex:
        return {
            adding_kernel_arguments_to_nodes_message(nodes_type=nodes_type): {
                "res": False,
                "err": f"Failed to add {new_kernel_argument} kernel argument to {test_node_name} node: {ex}",
            }
        }

    return kernel_argument_task_dict


def adding_realtime_kernel_to_nodes(
    client: DynamicClient,
    logger: logging.Logger,
    nodes_type: str,
) -> Dict[str, Dict[str, Union[str, bool]]]:
    def is_realtime_kernel_added(kernel_info: str) -> bool:
        return "PREEMPT_RT" in kernel_info

    logger.debug(adding_realtime_kernel_to_nodes_message(nodes_type=nodes_type))

    realtime_str = "realtime"

    realtime_kernel_task_dict = {
        adding_realtime_kernel_to_nodes_message(nodes_type=nodes_type): create_ocp_resource(
            ocp_resource=MachineConfig(
                client=client,
                name=f"99-{nodes_type}-{realtime_str}",
                label={MACHINE_CONFIGURATION_ROLE_LABEL: nodes_type},
                kernel_type=realtime_str,
            ),
            logger=logger,
        )
    }

    test_node_name = get_test_node_name(client=client, nodes_type=nodes_type)
    try:
        wait_for_node_condition(
            timeout=TIMEOUT_30MIN,
            node_name=test_node_name,
            node_command="uname -a",
            condition_met=is_realtime_kernel_added,
        )
    except Exception as ex:
        return {
            adding_realtime_kernel_to_nodes_message(nodes_type=nodes_type): {
                "res": False,
                "err": f"Failed to add {realtime_str} kernel to {test_node_name} node: {ex}",
            }
        }

    return realtime_kernel_task_dict


def configure_journald_setting_on_nodes(
    client: DynamicClient,
    logger: logging.Logger,
    nodes_type: str,
) -> Dict[str, Dict[str, Union[str, bool]]]:
    def is_journald_setting_configured(journal_conf_output: str) -> bool:
        return journald_conf == journal_conf_output

    logger.debug(configure_journald_setting_on_nodes_message(nodes_type=nodes_type))

    journald_conf = """
    # Disable rate limiting
    RateLimitInterval=1s
    RateLimitBurst=10000
    Storage=volatile
    Compress=no
    MaxRetentionSec=30s
    """

    journald_conf_path = "/etc/systemd/journald.conf"

    journald_task_dict = {
        configure_journald_setting_on_nodes_message(nodes_type=nodes_type): create_ocp_resource(
            ocp_resource=MachineConfig(
                client=client,
                name=f"40-{nodes_type}-custom-journald",
                label={MACHINE_CONFIGURATION_ROLE_LABEL: nodes_type},
                config={
                    "ignition": {"config": {}, "security": {"tls": {}}, "timeouts": {}},
                    "version": "3.1.0",
                    "networkd": {},
                    "passwd": {},
                    "storage": {
                        "files": [
                            {
                                "contents": {
                                    "source": f"data:text/plain;charset=utf-8;base64,{str_b64encode(str_to_encode=journald_conf)}",
                                    "verification": {},
                                },
                                "filesystem": "root",
                                "mode": 420,
                                "path": journald_conf_path,
                            }
                        ]
                    },
                },
            ),
            logger=logger,
        )
    }
    test_node_name = get_test_node_name(client=client, nodes_type=nodes_type)
    try:
        wait_for_node_condition(
            timeout=TIMEOUT_30MIN,
            node_name=test_node_name,
            node_command=f"cat {journald_conf_path}",
            condition_met=is_journald_setting_configured,
        )
    except Exception as ex:
        return {
            configure_journald_setting_on_nodes_message(nodes_type=nodes_type): {
                "res": False,
                "err": f"Failed to configure journald setting on {test_node_name} node: {ex}",
            }
        }

    return journald_task_dict


def configure_image_registry_setting_on_nodes(
    client: DynamicClient,
    logger: logging.Logger,
    nodes_type: str,
) -> Dict[str, Dict[str, Union[str, bool]]]:
    def is_image_registry_setting_configured(registries_conf_output: str) -> bool:
        return registries_conf == registries_conf_output

    logger.debug(configure_image_registry_setting_on_nodes_message(nodes_type=nodes_type))

    registries_conf = """
    unqualified-search-registries = ['registry.access.redhat.com', 'docker.io', 'quay.io']
    """
    search_registries_machine_config_name = f"99-{nodes_type}-unqualified-search-registries"
    search_registries_conf_path = f"/etc/containers/registries.conf.d/{search_registries_machine_config_name}.conf"

    image_registries_task_dict = {
        configure_image_registry_setting_on_nodes_message(nodes_type=nodes_type): create_ocp_resource(
            ocp_resource=MachineConfig(
                client=client,
                name=search_registries_machine_config_name,
                label={MACHINE_CONFIGURATION_ROLE_LABEL: nodes_type},
                config={
                    "ignition": {
                        "version": "3.1.0",
                        "storage": {
                            "files": [
                                {
                                    "contents": {
                                        "source": f"data:text/plain;charset=utf-8;base64,{str_b64encode(str_to_encode=registries_conf)}"
                                    },
                                    "filesystem": "root",
                                    "mode": "0644",
                                    "path": search_registries_conf_path,
                                }
                            ]
                        },
                    }
                },
            ),
            logger=logger,
        )
    }
    test_node_name = get_test_node_name(client=client, nodes_type=nodes_type)
    try:
        wait_for_node_condition(
            timeout=TIMEOUT_30MIN,
            node_name=test_node_name,
            node_command=f"cat {search_registries_conf_path}",
            condition_met=is_image_registry_setting_configured,
        )
    except Exception as ex:
        return {
            configure_image_registry_setting_on_nodes_message(nodes_type=nodes_type): {
                "res": False,
                "err": f"Failed to configure images registry setting on {test_node_name} node: {ex}",
            }
        }

    return image_registries_task_dict


def adding_extensions_to_rhcos_on_nodes(
    client: DynamicClient,
    logger: logging.Logger,
    nodes_type: str,
) -> Dict[str, Dict[str, Union[str, bool]]]:
    def is_extensions_added_to_rhcos(is_usbguard_installed: str) -> bool:
        return "is not installed" not in is_usbguard_installed

    logger.debug(adding_extensions_to_rhcos_on_nodes_message(nodes_type=nodes_type))

    rhcos_extension_name: str = "usbguard"

    rhcos_extensions_task_dict = {
        adding_extensions_to_rhcos_on_nodes_message(nodes_type=nodes_type): create_ocp_resource(
            ocp_resource=MachineConfig(
                client=client,
                name=f"80-{nodes_type}-extensions",
                label={MACHINE_CONFIGURATION_ROLE_LABEL: nodes_type},
                config={"ignition": {"version": "3.1.0", "extensions": [rhcos_extension_name]}},
            ),
            logger=logger,
        )
    }
    # TODO: check why RHCOS extensions are not added properly
    test_node_name = get_test_node_name(client=client, nodes_type=nodes_type)
    try:
        wait_for_node_condition(
            timeout=TIMEOUT_30MIN,
            node_name=test_node_name,
            node_command=f"rpm -q {rhcos_extension_name}",
            condition_met=is_extensions_added_to_rhcos,
        )
    except Exception as ex:
        return {
            adding_extensions_to_rhcos_on_nodes_message(nodes_type=nodes_type): {
                "res": False,
                "err": f"Failed to add {rhcos_extension_name} extension to rhcos on {nodes_type} nodes: {ex}",
            }
        }

    return rhcos_extensions_task_dict


# TODO: Add task for adding custom firmware blobs to nodes here


def execute_nodes_configuration(
    config: Dict[str, Any],
    logger: logging.Logger,
    client: DynamicClient,
    progress: Optional[Progress] = None,
) -> Dict[str, Dict[str, Union[str, bool]]]:
    nodes_configurator_description: str = "Configure nodes using MachineConfig"
    logger.debug(nodes_configurator_description)

    cluster_domain: Optional[str] = config.get("cluster_domain")

    return execute_configurator(
        verify_and_execute_kwargs={
            "config": config,
            "logger_obj": logger,
            "progress": progress,
            "logger": logger,
        },
        tasks_dict={
            configure_chrony_ntp_on_nodes_message(nodes_type=MASTER_NODE_TYPE): {
                "func": configure_chrony_ntp_on_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "cluster_domain": cluster_domain,
                    "nodes_type": MASTER_NODE_TYPE,
                },
            },
            configure_chrony_ntp_on_nodes_message(nodes_type=WORKER_NODE_TYPE): {
                "func": configure_chrony_ntp_on_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "cluster_domain": cluster_domain,
                    "nodes_type": WORKER_NODE_TYPE,
                },
            },
            adding_kernel_arguments_to_nodes_message(nodes_type=MASTER_NODE_TYPE): {
                "func": adding_kernel_arguments_to_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": MASTER_NODE_TYPE,
                },
            },
            adding_kernel_arguments_to_nodes_message(nodes_type=WORKER_NODE_TYPE): {
                "func": adding_kernel_arguments_to_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": WORKER_NODE_TYPE,
                },
            },
            adding_realtime_kernel_to_nodes_message(nodes_type=MASTER_NODE_TYPE): {
                "func": adding_realtime_kernel_to_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": MASTER_NODE_TYPE,
                },
            },
            adding_realtime_kernel_to_nodes_message(nodes_type=WORKER_NODE_TYPE): {
                "func": adding_realtime_kernel_to_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": WORKER_NODE_TYPE,
                },
            },
            configure_journald_setting_on_nodes_message(nodes_type=MASTER_NODE_TYPE): {
                "func": configure_journald_setting_on_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": MASTER_NODE_TYPE,
                },
            },
            configure_journald_setting_on_nodes_message(nodes_type=WORKER_NODE_TYPE): {
                "func": configure_journald_setting_on_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": WORKER_NODE_TYPE,
                },
            },
            configure_image_registry_setting_on_nodes_message(nodes_type=MASTER_NODE_TYPE): {
                "func": configure_image_registry_setting_on_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": MASTER_NODE_TYPE,
                },
            },
            configure_image_registry_setting_on_nodes_message(nodes_type=WORKER_NODE_TYPE): {
                "func": configure_image_registry_setting_on_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": WORKER_NODE_TYPE,
                },
            },
            adding_extensions_to_rhcos_on_nodes_message(nodes_type=MASTER_NODE_TYPE): {
                "func": adding_extensions_to_rhcos_on_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": MASTER_NODE_TYPE,
                },
            },
            adding_extensions_to_rhcos_on_nodes_message(nodes_type=WORKER_NODE_TYPE): {
                "func": adding_extensions_to_rhcos_on_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": WORKER_NODE_TYPE,
                },
            },
        },
        description=nodes_configurator_description,
    )
