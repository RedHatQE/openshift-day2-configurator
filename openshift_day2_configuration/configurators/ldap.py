import shlex
from typing import Dict

from ocp_resources.cluster_role_binding import ClusterRoleBinding
from ocp_resources.oauth import OAuth
from ocp_resources.resource import ResourceEditor
from pyhelper_utils.shell import run_command

from openshift_day2_configuration.utils.general import (
    DAY2_CONFIGURATORS,
    set_logger,
    verify_and_execute_configurator,
)

LOGGER = set_logger(name="ldap-config")
LDAP_CONFIG = DAY2_CONFIGURATORS.get("ldap")


@verify_and_execute_configurator(config=LDAP_CONFIG, config_keys=["bind_password"], logger=LOGGER)
def create_ldap_secret(bind_password: str) -> Dict:
    cmd = shlex.split(
        f"oc create secret generic ldap-secret --from-literal=bindPassword={bind_password} -n openshift-config"
    )
    res, _, err = run_command(command=cmd, check=False)

    return {"res": res, "err": err}


@verify_and_execute_configurator(config=LDAP_CONFIG, config_keys=["idp_name", "bind_password"], logger=LOGGER)
def update_cluster_oath(bind_dn_name: str, bind_password: str, url: str) -> Dict:
    cluster_oath = OAuth(name="cluster")

    if not cluster_oath.exists:
        LOGGER.error(f"Cluster OAuth {cluster_oath.name} does not exist")
        return {
            "res": False,
            "err": f"Cluster OAuth {cluster_oath.name} does not exist",
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
                    "bindPassword": bind_password,
                    "insecure": True,
                    "url": url,
                },
            }
        ]
    }
    ResourceEditor({cluster_oath: {"spec": {oath_dict}}}).update()

    return {"res": True, "err": None}


def disable_self_provisioners() -> Dict:
    self_provisioner_rb = ClusterRoleBinding(name="self-provisioner")

    status_dict = {}

    # TODO: YP - this rolebinding does not exist (tested on AWS-OSD and HCP)
    if self_provisioner_rb.exists:
        status_dict["Set role binding subjects to null"] = set_role_binding_subjects_null(
            self_provisioner_rb=self_provisioner_rb
        )
    else:
        status_dict["Self provisioners not found"] = {
            "res": False,
            "err": f"ClusterRoleBinding {self_provisioner_rb.name} does not exist",
        }

    status_dict["Remove role binding"] = remove_role_binding_from_group(self_provisioner_rb=self_provisioner_rb)

    # TODO - YP: check if the order matters or this action can be moved under the first resource.exists check
    if self_provisioner_rb.exists:
        status_dict["Set role binding autoupdate"] = set_role_binding_autoupdate_false(
            self_provisioner_rb=self_provisioner_rb
        )

    return status_dict


@verify_and_execute_configurator(logger=LOGGER)
def set_role_binding_autoupdate_false(self_provisioner_rb: ClusterRoleBinding) -> Dict:
    LOGGER.debug(f"Patch clusterrolebinding {self_provisioner_rb.name}: autoupdate: false")
    ResourceEditor({
        self_provisioner_rb: {"metadata": {"rbac.authorization.kubernetes.io/autoupdate": "false"}}
    }).update()

    return {"res": True, "err": None}


@verify_and_execute_configurator(logger=LOGGER)
def remove_role_binding_from_group(self_provisioner_rb: ClusterRoleBinding) -> Dict:
    LOGGER.debug(f"Remove role binding {self_provisioner_rb.name} from group system:authenticated:oauth")
    # TODO - YP: the following warning when running the command in the doc:
    # Warning: Your changes may get lost whenever a master is restarted,
    # unless you prevent reconciliation of this rolebinding using the following command:
    # oc amd comment in cli: oc annotate clusterrolebinding.rbac self-provisioners
    # 'rbac.authorization.kubernetes.io/autoupdate=false' --overwrite --local
    cmd = shlex.split(
        f"oc adm policy remove-cluster-role-from-group {self_provisioner_rb.name} system:authenticated:oauth"
    )
    res, _, err = run_command(command=cmd, check=False)

    return {"res": res, "err": err}


@verify_and_execute_configurator(logger=LOGGER)
def set_role_binding_subjects_null(self_provisioner_rb: ClusterRoleBinding) -> Dict:
    LOGGER.debug(f"Patch clusterrolebinding {self_provisioner_rb.name}: 'subjects'= 'null'")
    ResourceEditor({self_provisioner_rb: {"subjects": "null"}}).update()

    return {"res": True, "err": None}


def execute_ldap_configuration(config: Dict) -> Dict:
    LOGGER.debug("Configuring LDAP")

    status_dict = {
        "Create LDAP secret": create_ldap_secret(
            bind_password=config.get("bind_password"),
        ),
        "Create OAuth": update_cluster_oath(
            bind_dn_name=config.get("bind_dn_name"), bind_password=config.get("bind_password"), url=config.get("url")
        ),
    }

    status_dict.update(disable_self_provisioners())

    # TODO: Configure LDAP Groups with Active Directory section

    return status_dict
