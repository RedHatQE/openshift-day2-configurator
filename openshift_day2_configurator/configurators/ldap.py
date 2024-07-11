from __future__ import annotations

import base64
import logging
import shlex
from typing import Any, Dict, List

from kubernetes.dynamic import DynamicClient
from ocp_resources.cluster_role import ClusterRole
from ocp_resources.cluster_role_binding import ClusterRoleBinding
from ocp_resources.configmap import ConfigMap
from ocp_resources.cron_job import CronJob
from ocp_resources.namespace import Namespace
from ocp_resources.oauth import OAuth
from ocp_resources.resource import ResourceEditor
from ocp_resources.secret import Secret
from ocp_resources.service_account import ServiceAccount
from ocp_resources.sealed_secret import SealedSecret
from pyhelper_utils.shell import run_command
from rich.progress import Progress

from openshift_day2_configurator.utils.general import (
    execute_configurator,
)
from openshift_day2_configurator.utils.resources import create_ocp_resource

CREATE_LDAP_SECRET_TASK_NAME: str = "Create LDAP secret"  # pragma: allowlist secret
UPDATE_OAUTH_TASK_NAME: str = "Update OAuth"
DISABLE_SELF_PROVISIONERS_TASK_NAME: str = "Disable self provisioners"
CREATE_LDAP_GROUPS_SYNC: str = "Create LDAP groups sync"


def create_ldap_secret(
    bind_password: str,
    logger: logging.Logger,
    client: DynamicClient,
) -> Dict[str, Dict[str, str]]:
    logger.debug(CREATE_LDAP_SECRET_TASK_NAME)

    return {
        CREATE_LDAP_SECRET_TASK_NAME: create_ocp_resource(
            ocp_resource=Secret(
                client=client,
                name="ldap-secret",
                namespace="openshift-config",
                data_dict={
                    "bindPassword": base64.b64encode(bind_password.encode()).decode(),
                },
                type="Opaque",
            ),
            logger=logger,
        )
    }


def update_cluster_oath(
    bind_dn_name: str, url: str, logger: logging.Logger, client: DynamicClient
) -> Dict[str, Dict[str, str | bool]]:
    logger.debug(UPDATE_OAUTH_TASK_NAME)
    cluster_oauth = OAuth(client=client, name="cluster")

    if not cluster_oauth.exists:
        logger.debug(f"Cluster OAuth {cluster_oauth.name} does not exist")
        return {
            UPDATE_OAUTH_TASK_NAME: {
                "res": False,
                "err": f"Cluster OAuth {cluster_oauth.name} does not exist",
            }
        }

    try:
        ResourceEditor({
            cluster_oauth: {
                "spec": {
                    "identityProviders": [
                        {
                            "name": "ldapidp",
                            "mappingMethod": "claim",
                            "type": "LDAP",
                            "ldap": {
                                "attributes": {
                                    "id": ["dn"],
                                    "email": ["mail"],
                                    "name": ["cn"],
                                    "preferredUsername": ["sAMAccountName"],
                                },
                                "bindDN": bind_dn_name,
                                "bindPassword": {"name": "ldap-secret"},
                                "insecure": True,
                                "url": url,
                            },
                        }
                    ]
                }
            }
        }).update()
    except Exception as ex:
        logger.debug(f"Failed to update cluster oauth with error {ex}")
        return {UPDATE_OAUTH_TASK_NAME: {"res": False, "err": str(ex)}}

    return {UPDATE_OAUTH_TASK_NAME: {"res": True, "err": ""}}


def disable_self_provisioners(logger: logging.Logger, client: DynamicClient) -> Dict[str, Dict[str, str | bool]]:
    self_provisioner_rb = ClusterRoleBinding(client=client, name="self-provisioner")
    logger.debug(DISABLE_SELF_PROVISIONERS_TASK_NAME)

    status_dict = {}

    # TODO: YP - this rolebinding does not exist (tested on AWS-OSD and HCP)
    if self_provisioner_rb.exists:
        status_dict["Set role binding subjects to null"] = set_role_binding_subjects_null(
            self_provisioner_rb=self_provisioner_rb, logger=logger
        )
    else:
        status_dict["Self provisioners not found"] = {
            "res": False,
            "err": f"ClusterRoleBinding {self_provisioner_rb.name} does not exist",
        }

    status_dict["Remove role binding"] = remove_role_binding_from_group(
        self_provisioner_rb=self_provisioner_rb, logger=logger
    )

    # TODO - YP: check if the order matters or this action can be moved under the first resource.exists check
    if self_provisioner_rb.exists:
        status_dict["Set role binding autoupdate"] = set_role_binding_autoupdate_false(
            self_provisioner_rb=self_provisioner_rb, logger=logger
        )

    return status_dict


def set_role_binding_autoupdate_false(
    self_provisioner_rb: ClusterRoleBinding, logger: logging.Logger
) -> Dict[str, str | bool]:
    logger.debug(f"Patch clusterrolebinding {self_provisioner_rb.name}: autoupdate: false")
    try:
        ResourceEditor({
            self_provisioner_rb: {"metadata": {"rbac.authorization.kubernetes.io/autoupdate": "false"}}
        }).update()
    except Exception as ex:
        logger.debug(f"Failed to patch clusterrolebinding {self_provisioner_rb.name} with error {ex}")
        return {"res": False, "err": str(ex)}

    return {"res": True, "err": ""}


def remove_role_binding_from_group(
    self_provisioner_rb: ClusterRoleBinding, logger: logging.Logger
) -> Dict[str, str | bool]:
    logger.debug(f"Remove role binding {self_provisioner_rb.name} from group system:authenticated:oauth")
    # TODO - YP: the following warning when running the command in the doc:
    # Warning: Your changes may get lost whenever a control plane is restarted,
    # unless you prevent reconciliation of this rolebinding using the following command:
    # oc amd comment in cli: oc annotate clusterrolebinding.rbac self-provisioners
    # 'rbac.authorization.kubernetes.io/autoupdate=false' --overwrite --local
    cmd: List[str] = shlex.split(
        f"oc adm policy remove-cluster-role-from-group {self_provisioner_rb.name} system:authenticated:oauth"
    )
    res, _, err = run_command(command=cmd, check=False)

    if not res:
        logger.debug(f"Failed to remove role binding {self_provisioner_rb.name} with error {err}")

    return {"res": res, "err": err.strip()}


def set_role_binding_subjects_null(
    self_provisioner_rb: ClusterRoleBinding, logger: logging.Logger
) -> Dict[str, str | bool]:
    logger.debug(f"Patch clusterrolebinding {self_provisioner_rb.name}: 'subjects'= 'null'")
    ResourceEditor({self_provisioner_rb: {"subjects": "null"}}).update()

    return {"res": True, "err": ""}


def create_ldap_groups_sync_cluster_role(
    name: str,
    logger: logging.Logger,
    client: DynamicClient,
) -> Dict[str, str | bool]:
    logger.debug(f"Create LDAP groups sync cluster role {name}")
    return create_ocp_resource(
        ocp_resource=ClusterRole(
            client=client,
            name=name,
            rules=[
                {
                    "apiGroups": ["", "user.openshift.io"],
                    "resources": ["groups"],
                    "verbs": ["get", "list", "create", "update"],
                }
            ],
        ),
        logger=logger,
    )


def create_ldap_groups_sync_cluster_role_binding(
    name: str,
    service_account_name: str,
    service_account_namespace: str,
    logger: logging.Logger,
    client: DynamicClient,
) -> Dict[str, str | bool]:
    logger.debug(f"Create LDAP groups sync cluster role binding {name}")
    return create_ocp_resource(
        ocp_resource=ClusterRoleBinding(
            client=client,
            name=name,
            cluster_role=service_account_name,
            subjects=[
                {
                    "kind": "ServiceAccount",
                    "name": service_account_name,
                    "namespace": service_account_namespace,
                }
            ],
        ),
        logger=logger,
    )


def create_ldap_groups_sync_service_account(
    name: str,
    service_account_namespace: str,
    logger: logging.Logger,
    client: DynamicClient,
) -> Dict[str, str | bool]:
    logger.debug(f"Create LDAP groups sync service account {name}")
    return create_ocp_resource(
        ocp_resource=ServiceAccount(client=client, name=name, namespace=service_account_namespace),
        logger=logger,
    )


def create_ldap_groups_sync_config_map(
    name: str,
    group_syncer_namespace: str,
    whitelist: str,
    logger: logging.Logger,
    client: DynamicClient,
) -> Dict[str, str | bool]:
    logger.debug(f"Create LDAP groups sync config map {name}")
    return create_ocp_resource(
        ocp_resource=ConfigMap(
            client=client,
            name=name,
            namespace=group_syncer_namespace,
            data={"whitelist.txt": whitelist},
        ),
        logger=logger,
    )


def create_ldap_groups_sync_cron_job(
    name: str,
    config_map_name: str,
    group_syncer_namespace: str,
    schedule: str,
    concurrency_policy: str,
    logger: logging.Logger,
    client: DynamicClient,
) -> Dict[str, str | bool]:
    logger.debug(f"Create LDAP groups sync cron job {name}")
    job_template = {
        "spec": {
            "backoffLimit": 0,
            "ttlSecondsAfterFinished": 1800,
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": name,
                            "image": "docker.jfrog-art-int/openshift/ose-cli:latest",
                            "command": [
                                "/bin/bash",
                                "-c",
                                "oc adm groups sync --whitelist=/etc/whitelist/whitelist.txt --sync-config=/etc/config/sync.yaml --confirm",
                            ],
                            "volumeMounts": [
                                {
                                    "mountPath": "/etc/config",
                                    "name": "ldap-sync-volume",
                                },
                                {"mountPath": "/etc/ldap-ca", "name": "ldap-ca"},
                                {
                                    "mountPath": "/etc/whitelist",
                                    "name": "ldap-sync-volume-whitelist",
                                },
                            ],
                        }
                    ],
                    "volumes": [
                        {
                            "name": "ldap-sync-volume",
                            "secret": {"secretName": name},
                        },
                        {
                            "name": "ldap-ca",
                            "configMap": {"name": "ca-config-map"},
                        },  # TODO: add ldap ca sa
                        {
                            "name": "ldap-sync-volume-whitelist",
                            "configMap": {"name": config_map_name},
                        },
                    ],
                    "restartPolicy": "Never",
                    "terminationGracePeriodSeconds": 30,
                    "activeDeadlineSeconds": 500,
                    "dnsPolicy": "ClusterFirst",
                    "serviceAccountName": name,
                }
            },
        }
    }

    return create_ocp_resource(
        ocp_resource=CronJob(
            client=client,
            name=name,
            namespace=group_syncer_namespace,
            schedule=schedule,
            concurrency_policy=concurrency_policy,
            job_template=job_template,
        ),
        logger=logger,
    )


def create_ldap_groups_sync_secret(
    name: str,
    group_syncer_namespace: str,
    sealed_sync_secret_encrypted_data: str,
    logger: logging.Logger,
    client: DynamicClient,
) -> Dict[str, str | bool]:
    logger.debug(f"Create LDAP groups sync secret {name}")

    try:
        return create_ocp_resource(
            ocp_resource=SealedSecret(
                client=client,
                name=name,
                namespace=group_syncer_namespace,
                encrypted_data={"sync.yaml": sealed_sync_secret_encrypted_data},
                template={
                    "metadata": {
                        "name": group_syncer_namespace,
                        "namespace": group_syncer_namespace,
                    }
                },
            ),
            logger=logger,
        )

    except Exception as ex:
        logger.debug(f"Failed to create SealedSecret {name} with error {ex}")
        return {"res": False, "err": str(ex)}


def create_ldap_groups_sync_namespace(
    group_syncer_namespace: str, logger: logging.Logger, client: DynamicClient
) -> Dict[str, str | bool]:
    logger.debug(f"Create LDAP groups sync namespace {group_syncer_namespace}")
    return create_ocp_resource(
        ocp_resource=Namespace(
            client=client,
            name=group_syncer_namespace,
        ),
        logger=logger,
    )


def create_ldap_groups_sync(
    group_syncer_name: str,
    group_syncer_namespace: str,
    group_syncer_whitelist: str,
    group_syncer_schedule: str,
    concurrency_policy: str,
    sealed_sync_secret_name: str,
    sealed_sync_secret_encrypted_data: str,
    logger: logging.Logger,
    client: DynamicClient,
) -> Dict[str, Dict[str, str | bool]]:
    service_account_namespace = "openshift-authentication"
    config_map_name = f"{group_syncer_name}-whitelist" if "whitelist" not in group_syncer_name else group_syncer_name
    status_dict = {
        "Create LDAP groups sync ClusterRole": create_ldap_groups_sync_cluster_role(
            name=group_syncer_name,
            logger=logger,
            client=client,
        ),
        "Create LDAP groups sync ClusterRoleBinding": create_ldap_groups_sync_cluster_role_binding(
            name=group_syncer_name,
            service_account_name=group_syncer_name,
            service_account_namespace=service_account_namespace,
            logger=logger,
            client=client,
        ),
        "Create LDAP group sync Namespace": create_ldap_groups_sync_namespace(
            group_syncer_namespace=group_syncer_namespace,
            logger=logger,
            client=client,
        ),
        "Create LDAP groups sync ServiceAccount": create_ldap_groups_sync_service_account(
            name=group_syncer_name,
            service_account_namespace=service_account_namespace,
            logger=logger,
            client=client,
        ),
        "Create LDAP groups sync ConfigMap": create_ldap_groups_sync_config_map(
            name=config_map_name,
            group_syncer_namespace=group_syncer_namespace,
            whitelist=group_syncer_whitelist,
            logger=logger,
            client=client,
        ),
        "Create LDAP groups sync Secret": create_ldap_groups_sync_secret(
            name=sealed_sync_secret_name,
            group_syncer_namespace=group_syncer_namespace,
            sealed_sync_secret_encrypted_data=sealed_sync_secret_encrypted_data,
            logger=logger,
            client=client,
        ),
        "Create LDAP groups sync CronJob": create_ldap_groups_sync_cron_job(
            name=group_syncer_name,
            config_map_name=config_map_name,
            group_syncer_namespace=group_syncer_namespace,
            schedule=group_syncer_schedule,
            concurrency_policy=concurrency_policy,
            logger=logger,
            client=client,
        ),
    }

    return status_dict


def execute_ldap_configuration(
    config: Dict[str, Any],
    logger: logging.Logger,
    client: DynamicClient,
    progress: Progress | None = None,
) -> Dict[str, Dict[str, str | bool]]:
    ldap_configurator_description: str = "Configuring LDAP"
    logger.debug(ldap_configurator_description)

    return execute_configurator(
        tasks_dict={
            CREATE_LDAP_SECRET_TASK_NAME: {
                "func": create_ldap_secret,
                "func_kwargs": {
                    "bind_password": config.get("bind_password"),
                    "client": client,
                },
            },
            UPDATE_OAUTH_TASK_NAME: {
                "func": update_cluster_oath,
                "func_kwargs": {
                    "bind_dn_name": config.get("bind_dn_name"),
                    "url": config.get("url"),
                    "client": client,
                },
            },
            DISABLE_SELF_PROVISIONERS_TASK_NAME: {
                "func": disable_self_provisioners,
                "func_kwargs": {"client": client},
            },
            CREATE_LDAP_GROUPS_SYNC: {
                "func": create_ldap_groups_sync,
                "func_kwargs": {
                    "group_syncer_name": config.get("group_syncer_name"),
                    "group_syncer_namespace": config.get("group_syncer_namespace"),
                    "group_syncer_whitelist": config.get("group_syncer_whitelist", ""),
                    "group_syncer_schedule": config.get("group_syncer_schedule"),
                    "concurrency_policy": config.get("group_syncer_concurrency_policy"),
                    "sealed_sync_secret_name": config.get("sealed_sync_secret_name"),
                    "sealed_sync_secret_encrypted_data": config.get("sealed_sync_secret_encrypted_data"),
                    "client": client,
                },
            },
        },
        verify_and_execute_kwargs={
            "config": config,
            "logger_obj": logger,
            "progress": progress,
            "logger": logger,
        },
        description=ldap_configurator_description,
    )
