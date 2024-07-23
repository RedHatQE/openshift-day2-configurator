import logging
from typing import Any, Dict, Union, Optional

from openshift_day2_configurator.utils.general import (
    execute_configurator,
    str_b64encode,
)
from rich.progress import Progress
from openshift_day2_configurator.utils.resources import create_ocp_resource
from kubernetes.dynamic import DynamicClient
from ocp_resources.machine_config import MachineConfig

MACHINE_CONFIGURATION_ROLE_LABEL: str = "machineconfiguration.openshift.io/role"


def configure_chrony_ntp_on_nodes_message(nodes_type: str) -> str:
    return f"Configure Chrony NTP on {nodes_type} nodes"


def adding_kernel_arguments_to_nodes_message(nodes_type: str) -> str:
    return f"Adding kernel arguments to {nodes_type} nodes"


def adding_realtime_kernel_to_nodes_message(nodes_type: str) -> str:
    return f"Adding real-time kernel to {nodes_type} nodes"


def configure_journald_setting_on_nodes_message(nodes_type: str) -> str:
    return f" Configure journald settings on {nodes_type} nodes"


def configure_image_registry_setting_on_nodes_message(nodes_type: str) -> str:
    return f"Configure image registry settings on {nodes_type} nodes"


def adding_extensions_to_rhcos_on_nodes_message(nodes_type: str) -> str:
    return f"Adding extensions to RHCOS on {nodes_type} nodes"


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
) -> Dict[str, Dict[str, str]]:
    logger.debug(adding_kernel_arguments_to_nodes_message(nodes_type=nodes_type))

    # TODO: assert kernel argument is added to random node
    return {
        adding_kernel_arguments_to_nodes_message(nodes_type=nodes_type): create_ocp_resource(
            ocp_resource=MachineConfig(
                client=client,
                name=f"05-{nodes_type}-kernelarg-selinuxpermissive",
                label={MACHINE_CONFIGURATION_ROLE_LABEL: nodes_type},
                config={
                    "ignition": {
                        "version": "3.1.0",
                        "kernelArguments": [
                            "enforcing=0"
                            # TODO: check why oc debug <worker-node> && cat /host/proc/cmdline doesnt show this arg
                        ],
                    }
                },
            ),
            logger=logger,
        )
    }


def adding_realtime_kernel_to_nodes(
    client: DynamicClient,
    logger: logging.Logger,
    nodes_type: str,
) -> Dict[str, Dict[str, str]]:
    logger.debug(adding_realtime_kernel_to_nodes_message(nodes_type=nodes_type))

    realtime_str = "realtime"

    # TODO: assert realtime kernel is added to random node
    return {
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


def configure_journald_setting_on_nodes(
    client: DynamicClient,
    logger: logging.Logger,
    nodes_type: str,
) -> Dict[str, Dict[str, str]]:
    logger.debug(configure_journald_setting_on_nodes_message(nodes_type=nodes_type))

    journald_conf = """
    # Disable rate limiting
    RateLimitInterval=1s
    RateLimitBurst=10000
    Storage=volatile
    Compress=no
    MaxRetentionSec=30s
    """

    # TODO: assert journald settings has changed on random node
    return {
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
                                "path": "/etc/systemd/journald.conf",
                            }
                        ]
                    },
                },
            ),
            logger=logger,
        )
    }


def configure_image_registry_setting_on_nodes(
    client: DynamicClient,
    logger: logging.Logger,
    nodes_type: str,
) -> Dict[str, Dict[str, str]]:
    logger.debug(configure_image_registry_setting_on_nodes_message(nodes_type=nodes_type))

    registries_conf = """
    unqualified-search-registries = ['registry.access.redhat.com', 'docker.io', 'quay.io']
    """
    search_registries_machine_config_name = f"99-{nodes_type}-unqualified-search-registries"

    # TODO: assert image registries are recongnized on a random node
    return {
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
                                    "path": f"/etc/containers/registries.conf.d/{search_registries_machine_config_name}.conf",
                                }
                            ]
                        },
                    }
                },
            ),
            logger=logger,
        )
    }


def adding_extensions_to_rhcos_on_nodes(
    client: DynamicClient,
    logger: logging.Logger,
    nodes_type: str,
) -> Dict[str, Dict[str, str]]:
    logger.debug(adding_extensions_to_rhcos_on_nodes_message(nodes_type=nodes_type))

    # TODO: assert extensions are added to RHCOS on random node
    return {
        adding_extensions_to_rhcos_on_nodes_message(nodes_type=nodes_type): create_ocp_resource(
            ocp_resource=MachineConfig(
                client=client,
                name=f"80-{nodes_type}-extensions",
                label={MACHINE_CONFIGURATION_ROLE_LABEL: nodes_type},
                config={"ignition": {"version": "3.1.0", "extensions": ["usbguard"]}},
            ),
            logger=logger,
        )
    }


# TODO: add task for Loading custom firmware blobs in the machine config manifest


def execute_nodes_configuration(
    config: Dict[str, Any],
    logger: logging.Logger,
    client: DynamicClient,
    progress: Optional[Progress] = None,
) -> Dict[str, Dict[str, Union[str, bool]]]:
    nodes_configurator_description: str = "Configure nodes using MachineConfig"
    logger.debug(nodes_configurator_description)

    cluster_domain: Optional[str] = config.get("cluster_domain")
    master_node_type: str = "master"
    worker_node_type: str = "worker"

    return execute_configurator(
        verify_and_execute_kwargs={
            "config": config,
            "logger_obj": logger,
            "progress": progress,
            "logger": logger,
        },
        tasks_dict={
            configure_chrony_ntp_on_nodes_message(nodes_type=master_node_type): {
                "func": configure_chrony_ntp_on_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "cluster_domain": cluster_domain,
                    "nodes_type": master_node_type,
                },
            },
            configure_chrony_ntp_on_nodes_message(nodes_type=worker_node_type): {
                "func": configure_chrony_ntp_on_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "cluster_domain": cluster_domain,
                    "nodes_type": worker_node_type,
                },
            },
            adding_kernel_arguments_to_nodes_message(nodes_type=master_node_type): {
                "func": adding_kernel_arguments_to_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": master_node_type,
                },
            },
            adding_kernel_arguments_to_nodes_message(nodes_type=worker_node_type): {
                "func": adding_kernel_arguments_to_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": worker_node_type,
                },
            },
            adding_realtime_kernel_to_nodes_message(nodes_type=master_node_type): {
                "func": adding_realtime_kernel_to_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": master_node_type,
                },
            },
            adding_realtime_kernel_to_nodes_message(nodes_type=worker_node_type): {
                "func": adding_realtime_kernel_to_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": worker_node_type,
                },
            },
            configure_journald_setting_on_nodes_message(nodes_type=master_node_type): {
                "func": configure_journald_setting_on_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": master_node_type,
                },
            },
            configure_journald_setting_on_nodes_message(nodes_type=worker_node_type): {
                "func": configure_journald_setting_on_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": worker_node_type,
                },
            },
            configure_image_registry_setting_on_nodes_message(nodes_type=master_node_type): {
                "func": configure_image_registry_setting_on_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": master_node_type,
                },
            },
            configure_image_registry_setting_on_nodes_message(nodes_type=worker_node_type): {
                "func": configure_image_registry_setting_on_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": worker_node_type,
                },
            },
        },
        description=nodes_configurator_description,
    )
