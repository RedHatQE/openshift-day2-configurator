import logging
from typing import Any, Dict


def create_ocp_resource(ocp_resource: Any, logger: logging.Logger) -> Dict[str, Any]:
    name = ocp_resource.name
    resource_kind = ocp_resource.kind

    try:
        if ocp_resource.exists:
            return {"res": False, "err": f"{resource_kind} {name} already exists"}
        else:
            ocp_resource.deploy()
            return {"res": True, "err": ""}

    except Exception as ex:
        _ex: str = str(ex) if isinstance(ex, Exception) else ex.__repr__()
        logger.debug(f"Failed to create {resource_kind} {name} with error {_ex}")
        return {"res": False, "err": _ex}
