import triage


def test_package_imports_and_has_version():
    assert isinstance(triage.__version__, str)
