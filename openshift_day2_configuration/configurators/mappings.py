def configurators_mappings() -> dict:
    """
    Mapping of configurators to their respective functions

    Needed to avoid a circular import

    Returns:
          dict: configurators and their respective functions

    """
    from openshift_day2_configuration.configurators.ldap import (
        execute_ldap_configuration,
    )

    return {"ldap": execute_ldap_configuration}
