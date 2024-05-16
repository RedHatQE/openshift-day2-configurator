from __future__ import annotations
from typing import Any, Dict


def configurators_mappings() -> Dict[str, Any]:
    from openshift_day2_configurator.configurators.ldap import (
        execute_ldap_configuration,
    )

    return {"ldap": execute_ldap_configuration}
