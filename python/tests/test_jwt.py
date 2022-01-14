import os

import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from src import JWT, keys_utils


@pytest.fixture
def rsa_key1_paths():
    return os.path.join("tests", "test_data", "key1-private.pem"), os.path.join(
        "tests", "test_data", "key1-public.pem"
    )


@pytest.fixture
def rsa_key2_paths():
    return os.path.join("tests", "test_data", "key2-private.pem"), os.path.join(
        "tests", "test_data", "key2-public.pem"
    )


def test_rsa_keys_generation_and_saving():
    private_key, public_key = keys_utils.generate_rsa_keys()
    assert isinstance(private_key, RSAPrivateKey)
    assert isinstance(public_key, RSAPublicKey)

    keys_utils.save_private_and_public_keys(private_key, ".", "test_key")
    path_to_saved_private_key = os.path.join(".", "test_key-private.pem")
    path_to_saved_public_key = os.path.join(".", "test_key-public.pem")
    assert os.path.exists(path_to_saved_private_key)
    assert os.path.exists(path_to_saved_public_key)

    os.remove(path_to_saved_private_key)
    os.remove(path_to_saved_public_key)


def test_rsa_keys_loading(rsa_key1_paths):
    path_to_private_key = rsa_key1_paths[0]
    path_to_public_key = rsa_key1_paths[1]

    private_key, public_key = keys_utils.load_private_and_public_keys(
        path_to_private_key
    )
    assert isinstance(private_key, RSAPrivateKey)
    assert isinstance(public_key, RSAPublicKey)

    public_key2 = keys_utils.load_public_key(path_to_public_key)
    assert isinstance(public_key2, RSAPublicKey)


def test_jwt__hmac():
    sample_claims = {"sample": "claim"}
    correct_key = "secret key"
    wrong_key = "wrong key"

    token = JWT.encode(sample_claims, correct_key, nbf=235.45, exp_after=300000)
    assert len(token.split(".")) == 3

    claims = JWT.decode(token, correct_key)
    assert claims == sample_claims

    with pytest.raises(ValueError):
        JWT.decode(token, wrong_key)


def test_jwt__rsa(rsa_key1_paths, rsa_key2_paths):
    sample_claims = {"sample": "claim"}
    private_key, correct_public_key = keys_utils.load_private_and_public_keys(
        rsa_key1_paths[0]
    )
    wrong_public_key = keys_utils.load_public_key(rsa_key2_paths[1])

    token = JWT.encode(
        sample_claims, private_key, nbf=235.45, exp_after=300000, algorithm="RS256"
    )
    assert len(token.split(".")) == 3

    claims = JWT.decode(token, correct_public_key)
    assert claims == sample_claims

    with pytest.raises(ValueError):
        JWT.decode(token, wrong_public_key)
