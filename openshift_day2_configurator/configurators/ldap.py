from __future__ import annotations
import logging
import shlex
from typing import Callable, Dict, List

from ocp_resources.cluster_role_binding import ClusterRoleBinding
from ocp_resources.oauth import OAuth
from ocp_resources.resource import ResourceEditor
from pyhelper_utils.shell import run_command
from rich.progress import Progress

from openshift_day2_configurator.utils.general import (
    verify_and_execute_configurator,
)


CREATE_LDAP_SECRET_TASK_NAME: str = "Create LDAP secret"  # pragma: allowlist secret
UPDATE_OAUTH_TASK_NAME: str = "Update OAuth"
DISABLE_SELF_PROVISIONERS_TASK_NAME: str = "Disable self provisioners"


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
    # Warning: Your changes may get lost whenever a master is restarted,
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


def execute_ldap_configuration(config: Dict, logger: logging.Logger, progress: Progress | None = None) -> Dict:
    logger.debug("Configuring LDAP")

    status_dict: Dict = {}
    task_id: int | None = None

    all_tasks: List[str] = [
        CREATE_LDAP_SECRET_TASK_NAME,
        UPDATE_OAUTH_TASK_NAME,
        DISABLE_SELF_PROVISIONERS_TASK_NAME,
    ]

    all_functions: List[Callable] = [
        create_ldap_secret,
        update_cluster_oath,
        disable_self_provisioners,
    ]
    func_kwargs: List[Dict] = [
        {"bind_password": config.get("bind_password")},
        {
            "bind_dn_name": config.get("bind_dn_name"),
            "url": config.get("url"),
        },
        {},
    ]

    verify_and_execute_kwargs: Dict = {
        "config": config,
        "logger_obj": logger,
        "progress": progress,
        "logger": logger,
    }

    if progress:
        task_id = progress.add_task(description="  Configuring LDAP", total=len(all_tasks))

    for _task, _func, _func_kwargs in zip(all_tasks, all_functions, func_kwargs):
        _kwargs: Dict = {**verify_and_execute_kwargs, **_func_kwargs}
        status_dict.update(verify_and_execute_configurator(func=_func, task_name=_task, **_kwargs))

        if progress and task_id is not None:
            progress.update(task_id, advance=1)

    if progress and task_id is not None:
        progress.update(task_id, advance=1)

    # TODO: Configure LDAP Groups with Active Directory section

    return status_dict
