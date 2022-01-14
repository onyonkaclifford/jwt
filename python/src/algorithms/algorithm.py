from abc import ABC, abstractmethod
from typing import Any, Callable, Dict


class Algorithm(ABC):
    def __init__(self, supported_algorithms: Dict[str, Callable]):
        self.supported_algorithms = supported_algorithms

    @abstractmethod
    def generate_signature(
        self, encoded_header: str, encoded_payload: str, algorithm: str, key: Any
    ) -> str:
        pass

    @abstractmethod
    def verify_signature(
        self,
        encoded_header: str,
        encoded_payload: str,
        algorithm: str,
        signature: str,
        key: Any,
    ) -> bool:
        pass

    def is_algorithm_supported(self, algorithm: str) -> bool:
        return True if algorithm in self.supported_algorithms.keys() else False
