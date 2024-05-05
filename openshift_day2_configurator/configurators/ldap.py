from __future__ import annotations
import logging
import shlex
from typing import Any, Dict, List

from ocp_resources.cluster_role import ClusterRole
from ocp_resources.cluster_role_binding import ClusterRoleBinding
from ocp_resources.configmap import ConfigMap
from ocp_resources.cron_job import CronJob
from ocp_resources.oauth import OAuth
from ocp_resources.resource import ResourceEditor
from ocp_resources.secret import Secret
from ocp_resources.service_account import ServiceAccount
from pyhelper_utils.shell import run_command
from rich.progress import Progress, TaskID

from openshift_day2_configurator.utils.general import (
    verify_and_execute_configurator,
)


CREATE_LDAP_SECRET_TASK_NAME: str = "Create LDAP secret"  # pragma: allowlist secret
UPDATE_OAUTH_TASK_NAME: str = "Update OAuth"
DISABLE_SELF_PROVISIONERS_TASK_NAME: str = "Disable self provisioners"
CREATE_LDAP_GROUPS_SYNC: str = "Create LDAP groups sync"


def create_ldap_secret(bind_password: str, logger: logging.Logger) -> Dict[str, Dict]:
    logger.debug(CREATE_LDAP_SECRET_TASK_NAME)
    cmd: List = shlex.split(
        f"oc create secret generic ldap-secret --from-literal=bindPassword={bind_password} -n openshift-config"
    )
    res, _, err = run_command(command=cmd, check=False)

    if not res:
        logger.debug(f"Failed to create LDAP secret with error {err}")

    return {CREATE_LDAP_SECRET_TASK_NAME: {"res": res, "err": err}}


def update_cluster_oath(bind_dn_name: str, url: str, logger: logging.Logger) -> Dict[str, Dict]:
    logger.debug(UPDATE_OAUTH_TASK_NAME)
    cluster_oath = OAuth(name="cluster")

    if not cluster_oath.exists:
        logger.debug(f"Cluster OAuth {cluster_oath.name} does not exist")
        return {
            UPDATE_OAUTH_TASK_NAME: {
                "res": False,
                "err": f"Cluster OAuth {cluster_oath.name} does not exist",
            }
        }

    oath_dict = {
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

    try:
        ResourceEditor({cluster_oath: {"spec": oath_dict}}).update()
    except Exception as ex:
        logger.debug(f"Failed to update cluster oauth with error {ex}")
        return {UPDATE_OAUTH_TASK_NAME: {"res": False, "err": str(ex)}}

    return {UPDATE_OAUTH_TASK_NAME: {"res": True, "err": None}}


def disable_self_provisioners(logger: logging.Logger) -> Dict[str, Dict]:
    self_provisioner_rb = ClusterRoleBinding(name="self-provisioner")
    logger.debug(DISABLE_SELF_PROVISIONERS_TASK_NAME)

    status_dict: Dict = {}

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


def set_role_binding_autoupdate_false(self_provisioner_rb: ClusterRoleBinding, logger: logging.Logger) -> Dict:
    logger.debug(f"Patch clusterrolebinding {self_provisioner_rb.name}: autoupdate: false")
    try:
        ResourceEditor({
            self_provisioner_rb: {"metadata": {"rbac.authorization.kubernetes.io/autoupdate": "false"}}
        }).update()
    except Exception as ex:
        logger.debug(f"Failed to patch clusterrolebinding {self_provisioner_rb.name} with error {ex}")
        return {"res": False, "err": str(ex)}

    return {"res": True, "err": None}


def remove_role_binding_from_group(self_provisioner_rb: ClusterRoleBinding, logger: logging.Logger) -> Dict:
    logger.debug(f"Remove role binding {self_provisioner_rb.name} from group system:authenticated:oauth")
    # TODO - YP: the following warning when running the command in the doc:
    # Warning: Your changes may get lost whenever a control plane is restarted,
    # unless you prevent reconciliation of this rolebinding using the following command:
    # oc amd comment in cli: oc annotate clusterrolebinding.rbac self-provisioners
    # 'rbac.authorization.kubernetes.io/autoupdate=false' --overwrite --local
    cmd: List = shlex.split(
        f"oc adm policy remove-cluster-role-from-group {self_provisioner_rb.name} system:authenticated:oauth"
    )
    res, _, err = run_command(command=cmd, check=False)

    if not res:
        logger.debug(f"Failed to remove role binding {self_provisioner_rb.name} with error {err}")

    return {"res": res, "err": err}


def set_role_binding_subjects_null(self_provisioner_rb: ClusterRoleBinding, logger: logging.Logger) -> Dict:
    logger.debug(f"Patch clusterrolebinding {self_provisioner_rb.name}: 'subjects'= 'null'")
    ResourceEditor({self_provisioner_rb: {"subjects": "null"}}).update()

    return {"res": True, "err": None}


def create_ldap_groups_sync_cluster_role(name: str, logger: logging.Logger):
    try:
        ClusterRole(name=name).deploy()
        return {"res": True, "err": None}

    except Exception as ex:
        logger.debug(f"Failed to create LDAP groups sync cluster role with error {ex}")
        return {"res": False, "err": str(ex)}


def create_ldap_groups_sync_cluster_role_binding(
    name: str,
    service_account_name: str,
    service_account_namespace: str,
    logger: logging.Logger,
):
    try:
        ClusterRoleBinding(
            name=name,
            subjects=[
                {
                    "kind": "ServiceAccount",
                    "name": service_account_name,
                    "namespace": service_account_namespace,
                }
            ],
        ).deploy()
        return {"res": True, "err": None}

    except Exception as ex:
        logger.debug(f"Failed to create LDAP groups sync cluster role binding with error {ex}")
        return {"res": False, "err": str(ex)}


def create_ldap_groups_sync_service_account(name: str, service_account_namespace: str, logger: logging.Logger):
    try:
        ServiceAccount(
            name=name,
            namespace=service_account_namespace,
        ).deploy()
        return {"res": True, "err": None}

    except Exception as ex:
        logger.debug(f"Failed to create LDAP groups sync service account with error {ex}")
        return {"res": False, "err": str(ex)}


def create_ldap_groups_sync_config_map(name: str, group_syncer_namespace: str, whitelist: str, logger: logging.Logger):
    try:
        ConfigMap(
            name=name,
            namespace=group_syncer_namespace,
            data={"whitelist.txt": whitelist},
        ).deploy()
        return {"res": True, "err": None}

    except Exception as ex:
        logger.debug(f"Failed to create LDAP groups sync service account with error {ex}")
        return {"res": False, "err": str(ex)}


def create_ldap_groups_sync_cron_job(
    name: str,
    config_map_name: str,
    group_syncer_namespace: str,
    schedule: str,
    concurrency_policy: str,
    logger: logging.Logger,
):
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
                        {"name": "ldap-ca", "configMap": {"name": "ca-config-map"}},  # TODO: add ldap ca sa
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
    try:
        CronJob(
            name=name,
            namespace=group_syncer_namespace,
            schedule=schedule,
            concurrency_policy=concurrency_policy,
            job_template=job_template,
        ).deploy()
        return {"res": True, "err": None}

    except Exception as ex:
        logger.debug(f"Failed to create LDAP groups sync service account with error {ex}")
        return {"res": False, "err": str(ex)}


def create_ldap_groups_sync_secret(
    name: str, group_syncer_namespace: str, sealed_sync_secret: str, logger: logging.Logger
):
    try:
        Secret(
            name=name,
            namespace=group_syncer_namespace,
            data={"sync.yaml": sealed_sync_secret},
            type="encryptedData",
        ).deploy()
        return {"res": True, "err": None}

    except Exception as ex:
        logger.debug(f"Failed to create LDAP groups sync service account with error {ex}")
        return {"res": False, "err": str(ex)}


def create_ldap_groups_sync(
    group_syncer_name: str,
    group_syncer_namespace: str,
    whitelist: str,
    schedule: str,
    concurrency_policy: str,
    sealed_sync_secret: str,
    logger: logging.Logger,
):
    service_account_namespace = "openshift-authentication"
    config_map_name = f"{group_syncer_name}-whitelist" if whitelist not in group_syncer_name else group_syncer_name
    status_dict = {
        "Create LDAP groups sync ClusterRole": create_ldap_groups_sync_cluster_role(
            name=group_syncer_name, logger=logger
        ),
        "Create LDAP groups sync ClusterRoleBinding": create_ldap_groups_sync_cluster_role_binding(
            name=group_syncer_name,
            service_account_name=group_syncer_name,
            service_account_namespace=service_account_namespace,
            logger=logger,
        ),
        "Create LDAP groups sync ServiceAccount": create_ldap_groups_sync_service_account(
            name=group_syncer_name,
            service_account_namespace=service_account_namespace,
            logger=logger,
        ),
        "Create LDAP groups sync ConfigMap": create_ldap_groups_sync_config_map(
            name=config_map_name,
            group_syncer_namespace=group_syncer_namespace,
            whitelist=whitelist,
            logger=logger,
        ),
        "Create LDAP groups sync Secret": create_ldap_groups_sync_secret(
            name=sealed_sync_secret,
            group_syncer_namespace=group_syncer_namespace,
            sealed_sync_secret=sealed_sync_secret,
            logger=logger,
        ),
        "Create LDAP groups sync CronJob": create_ldap_groups_sync_cron_job(
            name=group_syncer_name,
            config_map_name=config_map_name,
            group_syncer_namespace=group_syncer_namespace,
            schedule=schedule,
            concurrency_policy=concurrency_policy,
            logger=logger,
        ),
    }

    return status_dict


def execute_ldap_configuration(config: Dict, logger: logging.Logger, progress: Progress | None = None) -> Dict:
    logger.debug("Configuring LDAP")

    status_dict: Dict = {}
    task_id: TaskID | None = None

    tasks_dict: Dict[str, Dict[str, Any]] = {
        CREATE_LDAP_SECRET_TASK_NAME: {
            "func": create_ldap_secret,
            "func_kwargs": {"bind_password": config.get("bind_password")},
        },
        UPDATE_OAUTH_TASK_NAME: {
            "func": update_cluster_oath,
            "func_kwargs": {
                "bind_dn_name": config.get("bind_dn_name"),
                "url": config.get("url"),
            },
        },
        DISABLE_SELF_PROVISIONERS_TASK_NAME: {
            "func": disable_self_provisioners,
            "func_kwargs": {},
        },
        CREATE_LDAP_GROUPS_SYNC: {
            "func": create_ldap_groups_sync,
            "func_kwargs": {
                "group_syncer_name": config.get("group_syncer_name"),
                "group_syncer_namespace": config.get("group_syncer_namespace"),
                "whitelist": config.get("group_syncer_name_whitelist", ""),
                "schedule": config.get("group_syncer_schedule"),
                "concurrency_policy": config.get("group_syncer_concurrency_policy"),
                "sealed_sync_secret": config.get("sealed_sync_secret"),
            },
        },
    }

    verify_and_execute_kwargs: Dict = {
        "config": config,
        "logger_obj": logger,
        "progress": progress,
        "logger": logger,
    }

    if progress:
        task_id = progress.add_task(description="  Configuring LDAP", total=len(tasks_dict))

    for _task, _func_config in tasks_dict.items():
        _kwargs: Dict = {**verify_and_execute_kwargs, **_func_config["func_kwargs"]}
        status_dict.update(verify_and_execute_configurator(func=_func_config["func"], task_name=_task, **_kwargs))

        if progress and task_id is not None:
            progress.update(task_id, advance=1)

    if progress and task_id is not None:
        progress.update(task_id, advance=1)

    return status_dict
