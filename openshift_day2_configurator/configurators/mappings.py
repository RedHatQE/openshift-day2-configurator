from __future__ import annotations
from typing import Any, Dict


def configurators_mappings() -> Dict[str, Any]:
    from openshift_day2_configurator.configurators.ldap import (
        execute_ldap_configuration,
    )
    from openshift_day2_configurator.configurators.ingress import (
        execute_ingress_configuration,
    )
    from openshift_day2_configurator.configurators.nodes import (
        execute_nodes_configuration,
    )

    return {
        "ldap": execute_ldap_configuration,
        "ingress": execute_ingress_configuration,
        "nodes": execute_nodes_configuration,
    }
