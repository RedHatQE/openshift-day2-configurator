import shlex
from typing import Dict

from ocp_resources.cluster_role_binding import ClusterRoleBinding
from ocp_resources.resource import ResourceEditor
from pyhelper_utils.shell import run_command
from simple_logger.logger import get_logger

from openshift_day2_configuration.utils.general import (
    verify_and_execute_configurator,
)

LOGGER = get_logger(name="ldap-config")


class LdapConfigurator:
    def __init__(self, config):
        self.config = config

    @verify_and_execute_configurator(config_keys=["bind_password"], logger=LOGGER)
    def create_ldap_secret(self, bind_password: str) -> Dict:
        cmd = shlex.split(
            f"oc create secret generic ldap-secret --from-literal=bindPassword={bind_password} -n openshift-config"
        )
        res, _, err = run_command(command=cmd, check=False)

        return {"res": res, "err": err}

    @verify_and_execute_configurator(config_keys=["idp_name", "bind_password"], logger=LOGGER)
    def create_oath(self, idp_name: str, bind_password: str):
        pass

    def disable_self_provisioners(self) -> Dict:
        self_provisioner_rb = ClusterRoleBinding(name="self-provisioner")

        status_dict = {}

        if self_provisioner_rb.exists:
            status_dict["Set role binding subjects to null"] = self.set_role_binding_subjects_null(
                self_provisioner_rb=self_provisioner_rb
            )
        else:
            status_dict["Self provisioners not found"] = {
                "res": False,
                "err": f"ClusterRoleBinding {self_provisioner_rb.name} does not exist",
            }

        status_dict["Remove role binding"] = self.remove_role_binding_from_group(
            self_provisioner_rb=self_provisioner_rb
        )

        # TODO: check if the order matters or this action can be moved under the first resource.exists check
        if self_provisioner_rb.exists:
            status_dict["Set role binding autoupdate"] = self.set_role_binding_autoupdate_false(
                self_provisioner_rb=self_provisioner_rb
            )

        return status_dict

    @verify_and_execute_configurator(logger=LOGGER)
    def set_role_binding_autoupdate_false(self, self_provisioner_rb: ClusterRoleBinding) -> Dict:
        LOGGER.debug(f"Patch clusterrolebinding {self_provisioner_rb.name}: autoupdate: false")
        ResourceEditor({
            self_provisioner_rb: {"metadata": {"rbac.authorization.kubernetes.io/autoupdate": "false"}}
        }).update()

        return {"res": True, "err": None}

    @verify_and_execute_configurator(logger=LOGGER)
    def remove_role_binding_from_group(self, self_provisioner_rb: ClusterRoleBinding) -> Dict:
        LOGGER.debug(f"Remove role binding {self_provisioner_rb.name} from group system:authenticated:oauth")
        #  Warning: Your changes may get lost whenever a master is restarted, unless you prevent reconciliation of this rolebinding using the following command:
        # oc amd comment in cli: oc annotate clusterrolebinding.rbac self-provisioners 'rbac.authorization.kubernetes.io/autoupdate=false' --overwrite --local
        cmd = shlex.split(
            f"oc adm policy remove-cluster-role-from-group {self_provisioner_rb.name} system:authenticated:oauth"
        )
        res, _, err = run_command(command=cmd, check=False)

        return {"res": res, "err": err}

    @verify_and_execute_configurator(logger=LOGGER)
    def set_role_binding_subjects_null(self, self_provisioner_rb: ClusterRoleBinding) -> Dict:
        LOGGER.debug(f"Patch clusterrolebinding {self_provisioner_rb.name}: 'subjects'= 'null'")
        ResourceEditor({self_provisioner_rb: {"subjects": "null"}}).update()

        return {"res": True, "err": None}


def execute_ldap_configuration(config: Dict) -> Dict:
    LOGGER.info("Configuring LDAP")

    status_dict = {
        "Create LDAP secret": LdapConfigurator(config=config).create_ldap_secret(
            bind_password=config.get("bind_password"),
        ),
    }

    # create_oath(idp_name=config["idp_name"], bind_password=config["bind_password"])
    status_dict.update(LdapConfigurator(config=config).disable_self_provisioners())

    return status_dict
