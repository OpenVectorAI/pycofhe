"""Typing stubs for the  cryptosystem module"""

from __future__ import annotations

from typing import List, TypeVar, Union, overload, Generic

from pycofhe.tensor.tensor_core import GenericTensor

SecretKey = TypeVar("SecretKey")
SecretKeyShare = TypeVar("SecretKeyShare")
PublicKey = TypeVar("PublicKey")
PlainText = TypeVar("PlainText")
CipherText = TypeVar("CipherText")
PartialDecryptionResult = TypeVar("PartialDecryptionResult")

class CryptoSystem(
    Generic[
        SecretKey,
        SecretKeyShare,
        PublicKey,
        PlainText,
        CipherText,
        PartialDecryptionResult,
    ]
):
    """Python binding for CoFHE cryptosystem."""

    def __init__(
        self, security_level: int, k: int, compact: bool = False
    ) -> None:
        """
        Construct a CPUCryptoSystem with the specified security level (e.g. 128),
        message space 2^k, and a boolean for compact mode.

        Args:
            security_level (int): The security level in bits.
            k (int): The message space size (2^k).
            compact (bool): Whether to use compact mode.
        """
        ...

    @overload
    def keygen(self) -> SecretKey:
        """
        Generate a fresh secret key.

        Returns:
            SecretKey: The secret key.
        """
        ...

    @overload
    def keygen(self, sk: SecretKey) -> PublicKey:
        """
        Generate a public key from a given secret key.

        Args:
            sk (SecretKey): The secret key.

        Returns:
            PublicKey: The public key.
        """
        ...

    @overload
    def keygen(
        self, sk: SecretKey, threshold: int, num_parties: int
    ) -> List[List[SecretKeyShare]]:
        """
        Generate shares of a secret key (for threshold cryptography).

        Args:
            sk (SecretKey): The secret key.
            threshold (int): The threshold number of shares required to reconstruct the secret key.
            num_parties (int): The total number of parties.

        Returns:
            List[List[SecretKeyShare]]: The list of lists of secret key shares of each party for the threshold scheme.
        """
        ...

    @overload
    def keygen(
        self, sk: SecretKey = ..., threshold: int = ..., num_parties: int = ...
    ) -> Union[SecretKey, PublicKey, List[List[SecretKeyShare]]]: ...
    def encrypt(self, pk: PublicKey, pt: PlainText) -> CipherText:
        """
        Encrypt a plaintext using the given public key.

        Args:
            pk (PublicKey): The public key.
            pt (PlainText): The plaintext. Must be in the message space.

        Returns:
            CipherText: The ciphertext.
        """
        ...

    def encrypt_tensor(
        self, pk: PublicKey, pt_tensor: GenericTensor[PlainText]
    ) -> GenericTensor[CipherText]:
        """
        Encrypt a tensor of plaintexts using the given public key.

        Args:
            pk (PublicKey): The public key.
            pt_tensor (GenericTensor[PlainText]): The tensor of plaintexts.

        Returns:
            GenericTensor[CipherText]: The tensor of ciphertexts.
        """
        ...

    def decrypt(self, sk: SecretKey, ct: CipherText) -> PlainText:
        """
        Decrypt a ciphertext using the given secret key.

        Args:
            sk (SecretKey): The secret key.
            ct (CipherText): The ciphertext.

        Returns:
            PlainText: The plaintext.
        """
        ...

    def decrypt_tensor(
        self, sk: SecretKey, ct_tensor: GenericTensor[CipherText]
    ) -> GenericTensor[PlainText]:
        """
        Decrypt a tensor of ciphertexts using the given secret key.

        Args:
            sk (SecretKey): The secret key.
            ct_tensor (GenericTensor[CipherText]): The tensor of ciphertexts.

        Returns:
            GenericTensor[PlainText]: The tensor of plaintexts.
        """
        ...

    def part_decrypt(
        self, sks: List[SecretKeyShare], ct: CipherText
    ) -> PartialDecryptionResult:
        """
        Perform partial decryption given secret key shares and a ciphertext.

        Args:
            sks (List[SecretKeyShare]): The list of secret key shares.
            ct (CipherText): The ciphertext.

        Returns:
            PartialDecryptionResult: The partial decryption result.
        """
        ...

    def part_decrypt_tensor(
        self,
        sks: List[SecretKeyShare],
        ct_tensor: GenericTensor[CipherText],
    ) -> GenericTensor[PartialDecryptionResult]:
        """
        Perform partial decryption on a tensor of ciphertexts.

        Args:
            sks (List[SecretKeyShare]): The list of secret key shares.
            ct_tensor (GenericTensor[CipherText]): The tensor of ciphertexts.

        Returns:
            GenericTensor[PartialDecryptionResult]: The tensor of partial decryption results.
        """
        ...

    def combine_partial_decryption_results(
        self, ct: CipherText, pdrs: List[PartialDecryptionResult]
    ) -> PlainText:
        """
        Combine partial decryption results to recover the plaintext.

        Args:
            ct (CipherText): The ciphertext.
            pdrs (List[PartialDecryptionResult]): The list of partial decryption results.

        Returns:
            PlainText: The plaintext.
        """
        ...

    def combine_partial_decryption_results_tensor(
        self,
        ct: CipherText,
        pdrs: List[GenericTensor[PartialDecryptionResult]],
    ) -> GenericTensor[PlainText]:
        """
        Combine partial decryption results on a tensor of ciphertexts.

        Args:
            ct (CipherText): The ciphertext.
            pdrs (List[GenericTensor[PartialDecryptionResult]]): The list of tensors of partial decryption results.

        Returns:
            GenericTensor[PlainText]: The tensor of plaintexts.
        """
        ...

    def add_ciphertexts(
        self, pk: PublicKey, ct1: CipherText, ct2: CipherText
    ) -> CipherText:
        """
        Homomorphically add two ciphertexts under the given public key.

        Args:
            pk (PublicKey): The public key.
            ct1 (CipherText): The first ciphertext.
            ct2 (CipherText): The second ciphertext.

        Returns:
            CipherText: The resulting ciphertext.
        """
        ...

    def scal_ciphertext(
        self, pk: PublicKey, s: PlainText, ct: CipherText
    ) -> CipherText:
        """
        Scale (multiply) a ciphertext by a plaintext scalar.

        Args:
            pk (PublicKey): The public key.
            s (PlainText): The plaintext scalar.
            ct (CipherText): The ciphertext.

        Returns:
            CipherText: The resulting ciphertext.
        """
        ...

    def add_ciphertext_tensors(
        self,
        pk: PublicKey,
        ct1: GenericTensor[CipherText],
        ct2: GenericTensor[CipherText],
    ) -> GenericTensor[CipherText]:
        """
        Homomorphically add two tensors of ciphertexts.

        Args:
            pk (PublicKey): The public key.
            ct1 (GenericTensor[CipherText]): The first tensor of ciphertexts.
            ct2 (GenericTensor[CipherText]): The second tensor of ciphertexts.

        Returns:
            GenericTensor[CipherText]: The resulting tensor of ciphertexts.
        """
        ...

    def scal_ciphertext_tensors(
        self,
        pk: PublicKey,
        pt_tensor: GenericTensor[PlainText],
        ct_tensor: GenericTensor[CipherText],
    ) -> GenericTensor[CipherText]:
        """
        Scale (multiply) a tensor of plaintexts by a tensor of ciphertexts.

        Args:
            pk (PublicKey): The public key.
            pt_tensor (GenericTensor[PlainText]): The tensor of plaintexts.
            ct_tensor (GenericTensor[CipherText]): The tensor of ciphertexts.

        Returns:
            GenericTensor[CipherText]: The resulting tensor of ciphertexts.
        """
        ...

    def add_plaintexts(self, pt1: PlainText, pt2: PlainText) -> PlainText:
        """
        Add two plaintexts.

        Args:
            pt1 (PlainText): The first plaintext.
            pt2 (PlainText): The second plaintext.

        Returns:
            PlainText: The resulting plaintext.
        """
        ...

    def multiply_plaintexts(self, pt1: PlainText, pt2: PlainText) -> PlainText:
        """
        Multiply two plaintexts.

        Args:
            pt1 (PlainText): The first plaintext.
            pt2 (PlainText): The second plaintext.

        Returns:
            PlainText: The resulting plaintext.
        """
        ...

    def add_plaintext_tensors(
        self,
        pt1: GenericTensor[PlainText],
        pt2: GenericTensor[PlainText],
    ) -> GenericTensor[PlainText]:
        """
        Add two tensors of plaintexts.

        Args:
            pt1 (GenericTensor[PlainText]): The first tensor of plaintexts.
            pt2 (GenericTensor[PlainText]): The second tensor of plaintexts.

        Returns:
            GenericTensor[PlainText]: The resulting tensor of plaintexts.
        """
        ...

    def multiply_plaintext_tensors(
        self,
        pt1: GenericTensor[PlainText],
        pt2: GenericTensor[PlainText],
    ) -> GenericTensor[PlainText]:
        """
        Multiply two tensors of plaintexts.

        Args:
            pt1 (GenericTensor[PlainText]): The first tensor of plaintexts.
            pt2 (GenericTensor[PlainText]): The second tensor of plaintexts.

        Returns:
            GenericTensor[PlainText]: The resulting tensor of plaintexts.
        """
        ...

    def negate_plaintext(self, s: PlainText) -> PlainText:
        """
        Negate (multiply by -1) a plaintext.

        Args:
            s (PlainText): The plaintext.

        Returns:
            PlainText: The resulting plaintext.
        """
        ...

    def negate_plaintext_tensor(
        self, pt: GenericTensor[PlainText]
    ) -> GenericTensor[PlainText]:
        """
        Negate (multiply by -1) a tensor of plaintexts.

        Args:
            pt (GenericTensor[PlainText]): The tensor of plaintexts.

        Returns:
            GenericTensor[PlainText]: The resulting tensor of plaintexts.
        """
        ...

    def negate_ciphertext(self, pk: PublicKey, ct: CipherText) -> CipherText:
        """
        Negate (multiply by -1) a ciphertext.

        Args:
            pk (PublicKey): The public key.
            ct (CipherText): The ciphertext.

        Returns:
            CipherText: The resulting ciphertext, i.e., the negation.
        """
        ...

    def negate_ciphertext_tensor(
        self, pk: PublicKey, ct: GenericTensor[CipherText]
    ) -> GenericTensor[CipherText]:
        """
        Negate (multiply by -1) a tensor of ciphertexts.

        Args:
            pk (PublicKey): The public key.
            ct (GenericTensor[CipherText]): The tensor of ciphertexts.

        Returns:
            GenericTensor[CipherText]: The resulting tensor of ciphertexts.
        """
        ...

    def make_plaintext(self, value: float) -> PlainText:
        """
        Convert a float into the integer-based plaintext representation.

        Args:
            value (float): The floating-point value.

        Returns:
            PlainText: The plaintext corresponding to the value.
        """
        ...

    def make_plaintext_tensor(
        self, shape: List[int], values: List[float]
    ) -> GenericTensor[PlainText]:
        """
        Convert a list of floats into a tensor of plaintexts.

        Args:
            shape (List[int]): The shape of the tensor.
            values (List[float]): The list of floating-point values.

        Returns:
            GenericTensor[PlainText]: The tensor of plaintexts corresponding to the values.
        """
        ...

    def get_float_from_plaintext(
        self, pt: PlainText, scaling_factor: int = 1, depth: int = 1
    ) -> float:
        """
        Convert a plaintext back into a floating-point approximation.

        Args:
            pt (PlainText): The plaintext.
            scaling_factor (int): The scaling factor.
            depth (int): The depth.

        Returns:
            float: The floating-point value.
        """
        ...

    def get_float_from_plaintext_tensor(
        self,
        pts: GenericTensor[PlainText],
        scaling_factor: int = 1,
        depth: int = 1,
    ) -> List[float]:
        """
        Convert a tensor of plaintexts back into a list of floating-point approximations.

        Args:
            pts (GenericTensor[PlainText]): The tensor of plaintexts.
            scaling_factor (int): The scaling factor.
            depth (int): The depth.

        Returns:
            List[float]: The list of floating-point values.
        """
        ...

    def serialize(self) -> str:
        """
        Serialize the cryptosystem object (including parameters).

        Returns:
            str: The serialized object.
        """
        ...

    @staticmethod
    def deserialize(data: str) -> CryptoSystem:
        """
        Deserialize a CryptoSystem instance from a string.

        Args:
            data (bytes): The serialized object.

        Returns:
            CryptoSystem: The deserialized cryptosystem.
        """
        ...

    def serialize_secret_key(self, sk: SecretKey) -> bytes:
        """
        Serialize a SecretKey into a string.

        Args:
            sk (SecretKey): The secret key.

        Returns:
            bytes: The serialized secret key.
        """
        ...

    def deserialize_secret_key(self, data: bytes) -> SecretKey:
        """
        Deserialize a SecretKey from a string.

        Args:
            data (str): The serialized secret key.

        Returns:
            SecretKey: The deserialized secret key.
        """
        ...

    def serialize_public_key(self, pk: PublicKey) -> bytes:
        """
        Serialize a PublicKey into a string.

        Args:
            pk (PublicKey): The public key.

        Returns:
            bytes: The serialized public key.
        """
        ...

    def deserialize_public_key(self, data: bytes) -> PublicKey:
        """
        Deserialize a PublicKey from a string.

        Args:
            data (bytes): The serialized public key.

        Returns:
            PublicKey: The deserialized public key.
        """
        ...

    def serialize_plaintext(self, pt: PlainText) -> bytes:
        """
        Serialize a PlainText into a string.

        Args:
            pt (PlainText): The plaintext.

        Returns:
            bytes: The serialized plaintext.
        """
        ...

    def deserialize_plaintext(self, data: bytes) -> PlainText:
        """
        Deserialize a PlainText from a string.

        Args:
            data (bytes): The serialized plaintext.

        Returns:
            PlainText: The deserialized plaintext.
        """
        ...

    def serialize_ciphertext(self, ct: CipherText) -> bytes:
        """
        Serialize a CipherText into a string.

        Args:
            ct (CipherText): The ciphertext.

        Returns:
            bytes: The serialized ciphertext.
        """
        ...

    def deserialize_ciphertext(self, data: bytes) -> CipherText:
        """
        Deserialize a CipherText from a string.

        Args:
            data (bytes): The serialized ciphertext.

        Returns:
            CipherText: The deserialized ciphertext.
        """
        ...

    def serialize_partial_decryption_result(
        self, pdr: PartialDecryptionResult
    ) -> bytes:
        """
        Serialize a PartialDecryptionResult into a string.

        Args:
            pdr (PartialDecryptionResult): The partial decryption result.

        Returns:
            bytes: The serialized partial decryption result.
        """
        ...

    def deserialize_partial_decryption_result(
        self, data: bytes
    ) -> PartialDecryptionResult:
        """
        Deserialize a PartialDecryptionResult from a string.

        Args:
            data (bytes): The serialized partial decryption result.

        Returns:
            PartialDecryptionResult: The deserialized partial decryption result.
        """
        ...

    def serialize_secret_key_share(self, sks: SecretKeyShare) -> bytes:
        """
        Serialize a SecretKeyShare into a string.

        Args:
            sks (SecretKeyShare): The secret key share.

        Returns:
            bytes: The serialized secret key share.
        """
        ...

    def deserialize_secret_key_share(self, data: bytes) -> SecretKeyShare:
        """
        Deserialize a SecretKeyShare from a string.

        Args:
            data (bytes): The serialized secret key share.

        Returns:
            SecretKeyShare: The deserialized secret key share.
        """
        ...

    def serialize_plaintext_tensor(
        self, pt_tensor: GenericTensor[PlainText]
    ) -> bytes:
        """
        Serialize a tensor of PlainTexts into a bytes object.

        Args:
            pt_tensor (GenericTensor[PlainText]): The tensor of plaintexts.

        Returns:
            bytes: The serialized tensor of plaintexts.
        """
        ...

    def deserialize_plaintext_tensor(
        self, data: bytes
    ) -> GenericTensor[PlainText]:
        """
        Deserialize a tensor of PlainTexts from a bytes object.

        Args:
            data (bytes): The serialized tensor of plaintexts.

        Returns:
            GenericTensor[PlainText]: The deserialized tensor of plaintexts.
        """
        ...

    def serialize_ciphertext_tensor(
        self, ct_tensor: GenericTensor[CipherText]
    ) -> bytes:
        """
        Serialize a tensor of CipherTexts into a bytes object.

        Args:
            ct_tensor (GenericTensor[CipherText]): The tensor of ciphertexts.

        Returns:
            bytes: The serialized tensor of ciphertexts.
        """
        ...

    def deserialize_ciphertext_tensor(
        self, data: bytes
    ) -> GenericTensor[CipherText]:
        """
        Deserialize a tensor of CipherTexts from a bytes object.

        Args:
            data (bytes): The serialized tensor of ciphertexts.

        Returns:
            GenericTensor[CipherText]: The deserialized tensor of ciphertexts.
        """
        ...

    def serialize_partial_decryption_result_tensor(
        self, pdr_tensor: GenericTensor[PartialDecryptionResult]
    ) -> bytes:
        """
        Serialize a tensor of PartDecryptionResults into a bytes object.

        Args:
            pdr_tensor (GenericTensor[PartialDecryptionResult]): The tensor of partial decryption results.

        Returns:
            bytes: The serialized tensor of partial decryption results.
        """
        ...

    def deserialize_partial_decryption_result_tensor(
        self, data: bytes
    ) -> GenericTensor[PartialDecryptionResult]:
        """
        Deserialize a tensor of PartDecryptionResults from a bytes object.

        Args:
            data (bytes): The serialized tensor of partial decryption results.

        Returns:
            GenericTensor[PartialDecryptionResult]: The deserialized tensor of partial decryption results.
        """
        ...

    def get_ciphertexts_from_ciphertext_tensor(
        self, ct_tensor: GenericTensor[CipherText]
    ) -> List[CipherText]:
        """
        Get a list of ciphertexts from a tensor of ciphertexts.

        Args:
            ct_tensor (GenericTensor[CipherText]): The tensor of ciphertexts.

        Returns:
            List[CipherText]: The list of ciphertexts.
        """
        ...
