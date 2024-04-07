from functools import wraps
from typing import Any, Dict, List, Optional
from logging import Logger

from pyaml_env import parse_config

DAY2_CONFIG = parse_config("/home/rnetser/git/openshift-day2-configuration/day2_configuration.yaml")
DAY2_CONFIGURATORS = DAY2_CONFIG.get("configurators")


def verify_and_execute_configurator(
    config: Optional[Dict] = None,
    config_keys: Optional[List] = None,
    logger: Optional[Logger] = None,
) -> Any:
    """
    Decorator to verify and execute configurator.

    Args:
        config (Dict): configuration.
        config_keys (List): list of keys that should be in the config.
        logger (Logger): logger to use, if not passed, logs will not be displayed.

    Returns:
        Any: the underline function return value.
    """

    def wrapper(func):
        @wraps(func)
        def inner(*args, **kwargs):
            try:
                if config_keys and (missing_keys := [_key for _key in config_keys if _key not in config]):
                    return {"res": False, "err": f"Missing config keys: {missing_keys}"}

                return func(*args, **kwargs)
            except Exception as ex:
                if logger:
                    logger.info(ex)
                return {"res": False, "err": str(ex)}

        return inner

    return wrapper
