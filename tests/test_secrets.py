import pickle
from pathlib import PurePosixPath

import pytest
from pydantic import ValidationError

from ops_deploy.core import SecretRef, SecretStore, SecretValues
from ops_deploy.core.secrets import MissingSecretKeysError

REF = SecretRef("secrets/prod/toy.yml")


def test_secret_ref_accepts_positional_and_keyword() -> None:
    assert SecretRef("secrets/prod/toy.yml") == SecretRef(path=PurePosixPath("secrets/prod/toy.yml"))
    assert str(REF) == "secrets/prod/toy.yml"


@pytest.mark.parametrize(
    "path",
    ["/etc/secrets.yml", "secrets/../../etc/shadow.yml", "secrets/prod/toy.json", "secrets/prod/toy"],
)
def test_secret_ref_rejects_unsafe_paths(path: str) -> None:
    with pytest.raises(ValidationError):
        SecretRef(path)


def test_secret_values_never_render_values() -> None:
    values = SecretValues(REF, {"django_secret_key": "s3cr3t-value", "token": "t0k3n"})
    for text in (repr(values), str(values), f"{values}", f"{values!r}"):
        assert "s3cr3t-value" not in text
        assert "t0k3n" not in text
        assert "django_secret_key" in text
    assert values["token"] == "t0k3n"
    assert dict(values) == {"django_secret_key": "s3cr3t-value", "token": "t0k3n"}
    assert values.ref == REF


def test_secret_values_copy_their_input() -> None:
    source = {"token": "a"}
    values = SecretValues(REF, source)
    source["token"] = "b"
    assert values["token"] == "a"


def test_require_reports_missing_and_empty_keys_without_values() -> None:
    values = SecretValues(REF, {"present": "x", "empty": ""})
    assert values.require(["present"]) is values
    with pytest.raises(MissingSecretKeysError, match="missing required keys: empty, absent"):
        values.require(["present", "empty", "absent"])


def test_secret_values_refuse_pickling() -> None:
    with pytest.raises(TypeError, match="must not be pickled"):
        pickle.dumps(SecretValues(REF, {"k": "v"}))


def test_store_protocol_is_structural() -> None:
    class DictStore:
        def load(self, ref: SecretRef) -> SecretValues:
            return SecretValues(ref, {"k": "v"})

    store = DictStore()
    assert isinstance(store, SecretStore)
    assert store.load(REF)["k"] == "v"
