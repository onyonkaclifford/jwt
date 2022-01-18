import os
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def generate_rsa_keys(
    public_exponent: int = 65537, key_size: int = 2048
) -> Tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate a private and public RSA key pair, the default arguments are the recommended arguments to be passed to
    this function

    :param public_exponent: a value of 3 or 65537 is recommended, though 65537 is chosen as the better recommendation
    :param key_size: a value that's a multiple of 256 and is greater than or equal to 2048 is recommended
    :return: a private and public RSA key pair
    """
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent, key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_and_public_keys(
    private_key: RSAPrivateKey,
    dir_to_save_to: str,
    name_of_key: str,
    password: str = None,
) -> None:
    """Save a private and public RSA key pair to a pem file

    :param private_key: an RSA private key, the public key is extracted from this key
    :param dir_to_save_to: the directory to save the private and public RSA keys
    :param name_of_key: name to identify the files the keys will be saved in
    :param password: password used during encryption of the private key
    """
    public_key = private_key.public_key()
    private_pem = (
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        if password is None
        else private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password.encode()
            ),
        ).decode()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    with open(os.path.join(dir_to_save_to, f"{name_of_key}-private.pem"), "w") as f:
        f.write(private_pem)

    with open(os.path.join(dir_to_save_to, f"{name_of_key}-public.pem"), "w") as f:
        f.write(public_pem)


def load_private_and_public_keys(
    path_to_private_key: str, password: str = None
) -> Tuple[RSAPrivateKey, RSAPublicKey]:
    """Load a private and public RSA key pair from a pem file, the public key is extracted from the private key

    :param path_to_private_key: location of the private key
    :param password: password used during encryption of the private key
    :return: a private and public RSA key pair
    """
    with open(path_to_private_key, "rb") as f:
        private_key = (
            serialization.load_pem_private_key(f.read(), password=password)
            if password is None
            else serialization.load_pem_private_key(
                f.read(), password=password.encode()
            )
        )
    public_key = private_key.public_key()
    return private_key, public_key


def load_public_key(path_to_public_key: str) -> RSAPublicKey:
    """Load a public RSA key from a pem file

    :param path_to_public_key: location of the public key
    :return: a public RSA key
    """
    with open(path_to_public_key, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key
