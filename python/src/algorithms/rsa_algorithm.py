from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from .algorithm import Algorithm


class RSAAlgorithm(Algorithm):
    def __init__(self):
        super().__init__(
            {"RS256": hashes.SHA256, "RS384": hashes.SHA384, "RS512": hashes.SHA512}
        )

    def generate_signature(
        self,
        encoded_header: str,
        encoded_payload: str,
        algorithm: str,
        private_key: RSAPrivateKey,
    ) -> str:
        return private_key.sign(
            f"{encoded_header}.{encoded_payload}".encode(),
            padding.PSS(
                mgf=padding.MGF1(self.supported_algorithms[algorithm]()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            self.supported_algorithms[algorithm](),
        ).hex()

    def verify_signature(
        self,
        encoded_header: str,
        encoded_payload: str,
        algorithm: str,
        signature: str,
        public_key: RSAPublicKey,
    ) -> bool:
        try:
            public_key.verify(
                bytes.fromhex(signature),
                f"{encoded_header}.{encoded_payload}".encode(),
                padding.PSS(
                    mgf=padding.MGF1(self.supported_algorithms[algorithm]()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                self.supported_algorithms[algorithm](),
            )
        except InvalidSignature:
            return False

        return True
