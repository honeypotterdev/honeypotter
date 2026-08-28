from honeypotter.utils import MetadataContainer


def test_metadata_container() -> None:
    metadata = MetadataContainer()

    metadata["key"] = "value"
    metadata["container"]["a"] = "b"
    metadata["container"]["c"] = "d"
    metadata["container"]["collection"] = [1, 2, 3]

    assert metadata == {"key": "value", "container": {"a": "b", "c": "d", "collection": [1, 2, 3]}}
