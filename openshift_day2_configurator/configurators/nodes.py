import shlex
import logging
from typing import Any, Dict, Union, Optional

from openshift_day2_configurator.utils.general import (
    execute_configurator,
    str_b64encode,
)
from rich.progress import Progress
from timeout_sampler import TimeoutSampler
from pyhelper_utils.shell import run_command
from openshift_day2_configurator.utils.resources import create_ocp_resource
from kubernetes.dynamic import DynamicClient
from ocp_resources.machine_config import MachineConfig
from ocp_resources.machine_config_pool import MachineConfigPool

MACHINE_CONFIGURATION_ROLE_LABEL: str = "machineconfiguration.openshift.io/role"
IGNITION_VERSION: str = "3.1.0"
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


def loading_custom_firmware_blobs_on_nodes_message(nodes_type: str) -> str:
    return f"Loading custom firmware blobs in the machine config manifest for {nodes_type} nodes"


def get_machine_config_pool(client: DynamicClient, nodes_type: str) -> MachineConfigPool:
    return [mcp for mcp in MachineConfigPool.get(dyn_client=client) if mcp.name == nodes_type][0]


def generate_firmware_machine_config_file(
    firmware_package_name: str,
    firmware_files_dir: str,
    butane_content: str,
) -> str:
    firmware_machine_config_file: str = f"{firmware_package_name}.yaml"

    run_command(
        command=shlex.split(f"butane -o {firmware_machine_config_file} --files-dir {firmware_files_dir}"),
        input=butane_content,
    )

    return firmware_machine_config_file


def wait_for_machine_config_pool_to_update(
    client: DynamicClient,
    nodes_type: str,
    node_operation_message: str,
    error_message: str,
    machine_config_name: str,
) -> Dict[str, Dict[str, Union[str, bool]]]:
    try:
        for mcp_sample in TimeoutSampler(
            wait_timeout=TIMEOUT_30MIN,
            sleep=10,
            func=get_machine_config_pool,
            client=client,
            nodes_type=nodes_type,
        ):
            if machine_config_name in [
                config_source["name"]
                for config_source in mcp_sample.instance.to_dict()["spec"]["configuration"]["source"]
            ]:
                mcp_sample.wait_for_condition(
                    condition=MachineConfigPool.Status.UPDATED,
                    status=MachineConfigPool.Condition.Status.TRUE,
                    timeout=TIMEOUT_30MIN,
                )
                break

    except Exception as ex:
        return {
            node_operation_message: {
                "res": False,
                "err": f"{error_message}: {ex}",
            }
        }

    return {
        node_operation_message: {
            "res": True,
            "err": "",
        }
    }


def configure_chrony_ntp_on_nodes(
    client: DynamicClient,
    logger: logging.Logger,
    cluster_domain: str,
    nodes_type: str,
) -> Dict[str, Dict[str, Union[str, bool]]]:
    logger.debug(configure_chrony_ntp_on_nodes_message(nodes_type=nodes_type))

    chrony_conf = f"""
    pool ntp.{cluster_domain} iburst driftfile /var/lib/chrony/drift makestep 1.0 3
    rtcsync
    logdir /var/log/chrony
    """

    machine_config_name = f"99-{nodes_type}s-chrony-configuration"

    chrony_ntp_task_dict = {
        configure_chrony_ntp_on_nodes_message(nodes_type=nodes_type): create_ocp_resource(
            ocp_resource=MachineConfig(
                client=client,
                name=machine_config_name,
                label={MACHINE_CONFIGURATION_ROLE_LABEL: nodes_type},
                config={
                    "ignition": {
                        "config": {},
                        "security": {"tls": {}},
                        "timeouts": {},
                        "version": IGNITION_VERSION,
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

    if not (
        chrony_updated_dict := wait_for_machine_config_pool_to_update(
            client=client,
            nodes_type=nodes_type,
            machine_config_name=machine_config_name,
            node_operation_message=configure_chrony_ntp_on_nodes_message(nodes_type=nodes_type),
            error_message=f"Failed to Configure chrony NTP on {nodes_type} nodes",
        )
    )[configure_chrony_ntp_on_nodes_message(nodes_type=nodes_type)]["res"]:
        return chrony_updated_dict

    logger.info(f"Configured chrony NTP on {nodes_type} nodes successfully.")

    return chrony_ntp_task_dict


def adding_kernel_arguments_to_nodes(
    client: DynamicClient,
    logger: logging.Logger,
    nodes_type: str,
) -> Dict[str, Dict[str, Union[str, bool]]]:
    logger.debug(adding_kernel_arguments_to_nodes_message(nodes_type=nodes_type))

    new_kernel_argument = "enforcing=0"

    machine_config_name = f"05-{nodes_type}-kernelarg-selinuxpermissive"

    kernel_argument_task_dict = {
        adding_kernel_arguments_to_nodes_message(nodes_type=nodes_type): create_ocp_resource(
            ocp_resource=MachineConfig(
                client=client,
                name=machine_config_name,
                label={MACHINE_CONFIGURATION_ROLE_LABEL: nodes_type},
                config={
                    "ignition": {
                        "version": IGNITION_VERSION,
                    }
                },
                kernel_arguments=[new_kernel_argument],
            ),
            logger=logger,
        )
    }

    if not (
        kernel_args_updated_dict := wait_for_machine_config_pool_to_update(
            client=client,
            nodes_type=nodes_type,
            machine_config_name=machine_config_name,
            node_operation_message=adding_kernel_arguments_to_nodes_message(nodes_type=nodes_type),
            error_message=f"Failed to add {new_kernel_argument} kernel argument to {nodes_type} nodes",
        )
    )[adding_kernel_arguments_to_nodes_message(nodes_type=nodes_type)]["res"]:
        return kernel_args_updated_dict

    logger.info(f"Added {new_kernel_argument} kernel argument to {nodes_type} nodes successfully.")

    return kernel_argument_task_dict


def adding_realtime_kernel_to_nodes(
    client: DynamicClient,
    logger: logging.Logger,
    nodes_type: str,
) -> Dict[str, Dict[str, Union[str, bool]]]:
    logger.debug(adding_realtime_kernel_to_nodes_message(nodes_type=nodes_type))

    realtime_str = "realtime"

    machine_config_name = f"99-{nodes_type}-{realtime_str}"

    realtime_kernel_task_dict = {
        adding_realtime_kernel_to_nodes_message(nodes_type=nodes_type): create_ocp_resource(
            ocp_resource=MachineConfig(
                client=client,
                name=machine_config_name,
                label={MACHINE_CONFIGURATION_ROLE_LABEL: nodes_type},
                kernel_type=realtime_str,
            ),
            logger=logger,
        )
    }

    if not (
        realtime_kernel_updated_dict := wait_for_machine_config_pool_to_update(
            client=client,
            nodes_type=nodes_type,
            machine_config_name=machine_config_name,
            node_operation_message=adding_realtime_kernel_to_nodes_message(nodes_type=nodes_type),
            error_message=f"Failed to add {realtime_str} kernel to {nodes_type} nodes",
        )
    )[adding_realtime_kernel_to_nodes_message(nodes_type=nodes_type)]["res"]:
        return realtime_kernel_updated_dict

    logger.info(f"Added {realtime_str} kernel to {nodes_type} nodes successfully.")

    return realtime_kernel_task_dict


def configure_journald_setting_on_nodes(
    client: DynamicClient,
    logger: logging.Logger,
    nodes_type: str,
) -> Dict[str, Dict[str, Union[str, bool]]]:
    logger.debug(configure_journald_setting_on_nodes_message(nodes_type=nodes_type))

    journald_conf = """
    # Disable rate limiting
    RateLimitInterval=1s
    RateLimitBurst=10000
    Storage=volatile
    Compress=no
    MaxRetentionSec=30s
    """

    machine_config_name = f"40-{nodes_type}-custom-journald"

    journald_task_dict = {
        configure_journald_setting_on_nodes_message(nodes_type=nodes_type): create_ocp_resource(
            ocp_resource=MachineConfig(
                client=client,
                name=machine_config_name,
                label={MACHINE_CONFIGURATION_ROLE_LABEL: nodes_type},
                config={
                    "ignition": {
                        "config": {},
                        "security": {"tls": {}},
                        "timeouts": {},
                        "version": IGNITION_VERSION,
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
                    }
                },
            ),
            logger=logger,
        )
    }

    if not (
        journald_updated_dict := wait_for_machine_config_pool_to_update(
            client=client,
            nodes_type=nodes_type,
            machine_config_name=machine_config_name,
            node_operation_message=configure_journald_setting_on_nodes_message(nodes_type=nodes_type),
            error_message=f"Failed to configure journald setting on {nodes_type} nodes",
        )
    )[configure_journald_setting_on_nodes_message(nodes_type=nodes_type)]["res"]:
        return journald_updated_dict

    logger.info(f"Configured journald setting on {nodes_type} nodes successfully.")

    return journald_task_dict


def configure_image_registry_setting_on_nodes(
    client: DynamicClient,
    logger: logging.Logger,
    nodes_type: str,
) -> Dict[str, Dict[str, Union[str, bool]]]:
    logger.debug(configure_image_registry_setting_on_nodes_message(nodes_type=nodes_type))

    registries_conf = """
    unqualified-search-registries = ['registry.access.redhat.com', 'docker.io', 'quay.io']
    """
    search_registries_machine_config_name = f"99-{nodes_type}-unqualified-search-registries"

    image_registries_task_dict = {
        configure_image_registry_setting_on_nodes_message(nodes_type=nodes_type): create_ocp_resource(
            ocp_resource=MachineConfig(
                client=client,
                name=search_registries_machine_config_name,
                label={MACHINE_CONFIGURATION_ROLE_LABEL: nodes_type},
                config={
                    "ignition": {
                        "version": IGNITION_VERSION,
                        "storage": {
                            "files": [
                                {
                                    "contents": {
                                        "source": f"data:text/plain;charset=utf-8;base64,{str_b64encode(str_to_encode=registries_conf)}"
                                    },
                                    "filesystem": "root",
                                    "mode": 0o644,
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

    if not (
        image_registries_updated_dict := wait_for_machine_config_pool_to_update(
            client=client,
            nodes_type=nodes_type,
            machine_config_name=search_registries_machine_config_name,
            node_operation_message=configure_image_registry_setting_on_nodes_message(nodes_type=nodes_type),
            error_message=f"Failed to configure images registry setting on {nodes_type} nodes",
        )
    )[configure_image_registry_setting_on_nodes_message(nodes_type=nodes_type)]["res"]:
        return image_registries_updated_dict

    logger.info(f"Configured image registry setting on {nodes_type} nodes successfully.")

    return image_registries_task_dict


def adding_extensions_to_rhcos_on_nodes(
    client: DynamicClient,
    logger: logging.Logger,
    nodes_type: str,
) -> Dict[str, Dict[str, Union[str, bool]]]:
    logger.debug(adding_extensions_to_rhcos_on_nodes_message(nodes_type=nodes_type))

    rhcos_extension_name: str = "usbguard"

    machine_config_name = f"80-{nodes_type}-extensions"
    rhcos_extensions_task_dict = {
        adding_extensions_to_rhcos_on_nodes_message(nodes_type=nodes_type): create_ocp_resource(
            ocp_resource=MachineConfig(
                client=client,
                name=machine_config_name,
                label={MACHINE_CONFIGURATION_ROLE_LABEL: nodes_type},
                config={"ignition": {"version": IGNITION_VERSION}},
                extensions=[rhcos_extension_name],
            ),
            logger=logger,
        )
    }

    if not (
        rhcos_extensions_updated_dict := wait_for_machine_config_pool_to_update(
            client=client,
            nodes_type=nodes_type,
            machine_config_name=machine_config_name,
            node_operation_message=adding_extensions_to_rhcos_on_nodes_message(nodes_type=nodes_type),
            error_message=f"Failed to add {rhcos_extension_name} extension to rhcos on {nodes_type} nodes",
        )
    )[adding_extensions_to_rhcos_on_nodes_message(nodes_type=nodes_type)]["res"]:
        return rhcos_extensions_updated_dict

    logger.info(f"Added {rhcos_extension_name} extension to rhcos on {nodes_type} nodes successfully.")

    return rhcos_extensions_task_dict


def loading_custom_firmware_blobs_on_nodes(
    client: DynamicClient,
    logger: logging.Logger,
    nodes_type: str,
    firmware_files_dir: str,
    firmware_blob_file: str,
) -> Dict[str, Dict[str, Union[str, bool]]]:
    logging.debug(loading_custom_firmware_blobs_on_nodes_message(nodes_type=nodes_type))

    firmware_package_name: str = f"98-{nodes_type}-firmware-blob"
    nodes_firmware_files_dir: str = "/var/lib/firmware"
    butane_content: str = f"""
    variant: openshift
    version: 4.9.0
    metadata:
      labels:
        {MACHINE_CONFIGURATION_ROLE_LABEL}: {nodes_type}
      name: {firmware_package_name}
    storage:
      files:
      - path: {nodes_firmware_files_dir}/{firmware_package_name}.bu
        contents:
          local: {firmware_blob_file}
        mode: 0644
    openshift:
      kernel_arguments:
      - 'firmware_class.path={nodes_firmware_files_dir}'
    """

    firmware_task_dict = {
        loading_custom_firmware_blobs_on_nodes_message(nodes_type=nodes_type): create_ocp_resource(
            MachineConfig(
                client=client,
                name=firmware_package_name,
                yaml_file=generate_firmware_machine_config_file(
                    firmware_package_name=firmware_package_name,
                    firmware_files_dir=firmware_files_dir,
                    butane_content=butane_content,
                ),
            ),
            logger=logger,
        )
    }

    if not (
        firmware_updated_dict := wait_for_machine_config_pool_to_update(
            client=client,
            nodes_type=nodes_type,
            machine_config_name=firmware_package_name,
            node_operation_message=loading_custom_firmware_blobs_on_nodes_message(nodes_type=nodes_type),
            error_message=f"Failed to load {firmware_package_name} custom firmware blob on {nodes_type} nodes",
        )
    )[loading_custom_firmware_blobs_on_nodes_message(nodes_type=nodes_type)]["res"]:
        return firmware_updated_dict

    logger.info(f"Loaded {firmware_package_name} custom firmware blob on {nodes_type} nodes successfully.")

    return firmware_task_dict


def execute_nodes_configuration(
    config: Dict[str, Any],
    logger: logging.Logger,
    client: DynamicClient,
    progress: Optional[Progress] = None,
) -> Dict[str, Dict[str, Union[str, bool]]]:
    nodes_configurator_description: str = "Configure nodes using MachineConfig"
    logger.debug(nodes_configurator_description)

    cluster_domain_str: str = "cluster_domain"
    firmware_files_dir_str: str = "firmware_files_dir"
    firmware_blob_file_str = "firmware_blob_file"

    cluster_domain: Optional[str] = config.get(cluster_domain_str)
    firmware_files_dir: Optional[str] = config.get(firmware_files_dir_str)
    firmware_blob_file: Optional[str] = config.get(firmware_blob_file_str)

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
                    cluster_domain_str: cluster_domain,
                    "nodes_type": MASTER_NODE_TYPE,
                },
            },
            configure_chrony_ntp_on_nodes_message(nodes_type=WORKER_NODE_TYPE): {
                "func": configure_chrony_ntp_on_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    cluster_domain_str: cluster_domain,
                    "nodes_type": WORKER_NODE_TYPE,
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
            adding_realtime_kernel_to_nodes_message(nodes_type=WORKER_NODE_TYPE): {
                "func": adding_realtime_kernel_to_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": WORKER_NODE_TYPE,
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
            configure_image_registry_setting_on_nodes_message(nodes_type=WORKER_NODE_TYPE): {
                "func": configure_image_registry_setting_on_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": WORKER_NODE_TYPE,
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
            loading_custom_firmware_blobs_on_nodes_message(nodes_type=WORKER_NODE_TYPE): {
                "func": loading_custom_firmware_blobs_on_nodes,
                "func_kwargs": {
                    "client": client,
                    "logger": logger,
                    "nodes_type": WORKER_NODE_TYPE,
                    firmware_files_dir_str: firmware_files_dir,
                    firmware_blob_file_str: firmware_blob_file,
                },
            },
        },
        description=nodes_configurator_description,
    )
