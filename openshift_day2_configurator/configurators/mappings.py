def configurators_mappings() -> dict:
    from openshift_day2_configurator.configurators.ldap import (
        execute_ldap_configuration,
    )

    return {"ldap": execute_ldap_configuration}
