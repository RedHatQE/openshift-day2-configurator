import logging
from typing import Any, Dict


def create_ocp_resource(ocp_resource: Any, logger: logging.Logger) -> Dict[str, Any]:
    name = ocp_resource.name

    try:
        if ocp_resource.exists:
            return {"res": False, "err": f"ClusterRole {name} already exists"}
        else:
            logger.debug(f"Create LDAP groups sync cluster role {name}")
            ocp_resource.deploy()
            return {"res": True, "err": None}

    except Exception as ex:
        logger.debug(f"Failed to create {ocp_resource.kind} {name} with error {ex}")
        return {"res": False, "err": ex.__repr__()}
