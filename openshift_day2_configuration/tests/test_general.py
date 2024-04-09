from openshift_day2_configuration.utils.general import base_table


def test_base_table():
    table = base_table()
    assert [col.header for col in table.columns] == [
        "Configurator",
        "Step",
        "Status",
        "Failure Reason",
    ]
