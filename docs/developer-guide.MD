# Adding a new configurator

- Add a new module under [configurators](../openshift_day2_configurator/configurators).  
  Example:

```
openshift_day2_configurator/configurators/ntp.py
```

- Add a new entry in [configuration example](../day2_configuration.example.yaml) under `configurators` and add relevant configurable parameters.  
  Example:

```
configurators:
    ntp:
        - enabled: true
```

- Under the new module, create:
  - `execute_<conifguratot-name>_configuration` function - this is the entry function that will be called by the main script.
    - Define a `tasks_dict` which includes the tasks (functions) to be executed with the following structure:
      - `{task_name: {"func": <function_name>, "func_kwargs": <function_kwargs>}}`
    - See [ldap.py](../openshift_day2_configurator/configurators/ldap.py) for an example.
  - Each task function should return a dictionary with the following structure:
    - {"task_name": {"res": True, "err": ""}} - on success
    - {"task_name": {"res": False, "err": str(ex)}} - on failure
- Add the new module to [configurators_mappings.py](../openshift_day2_configurator/configurators/mappings/configurators_mappings.py)
  under `configurators_mappings` dictionary.

# Tests
#### Run day2 configurator tool tests:
```bash
poetry run pytest openshift_day2_configurator/tests
```