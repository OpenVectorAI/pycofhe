#include <string>

#include <pybind11/functional.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <gmp.h>

#include "cofhe.hpp"
#include "tensor/tensor_pyb.hpp"

namespace py = pybind11;

using namespace CoFHE;
using SecretKey = CPUCryptoSystem::SecretKey;
using SecretKeyShare = CPUCryptoSystem::SecretKeyShare;
using PublicKey = CPUCryptoSystem::PublicKey;
using PlainText = CPUCryptoSystem::PlainText;
using CipherText = CPUCryptoSystem::CipherText;
using PartialDecryptionResult = CPUCryptoSystem::PartialDecryptionResult;

PYBIND11_MODULE(cpu_cryptosystem_core, m) {

    m.doc() = "Python binding for CoFHE CPU cryptosystem";

    py::class_<SecretKey>(m, "CPUCryptoSystemSecretKey");
    py::class_<SecretKeyShare>(m, "CPUCryptoSystemSecretKeyShare");
    // both secret key share and plaintext are mpz
    m.attr("CPUCryptoSystemPlainText") = m.attr("CPUCryptoSystemSecretKeyShare");
    py::class_<PublicKey>(m, "CPUCryptoSystemPublicKey");
    py::class_<CipherText>(m, "CPUCryptoSystemCipherText");
    py::class_<PartialDecryptionResult>(
        m, "CPUCryptoSystemPartialDecryptionResult");

    init_tensor_class_bindings<CPUCryptoSystem::PlainText*>(
        m, "CPUCryptoSystemPlainTextTensor");
    init_tensor_class_bindings<CPUCryptoSystem::CipherText*>(
        m, "CPUCryptoSystemCipherTextTensor");
    init_tensor_class_bindings<CPUCryptoSystem::PartialDecryptionResult*>(
        m, "CPUCryptoSystemPartialDecryptionResultTensor");

    py::class_<CPUCryptoSystem>(m, "CPUCryptoSystem")
        .def(py::init<uint32_t, uint32_t, bool>(), py::arg("security_level"),
             py::arg("k"), py::arg("compact") = false,
             R"pbdoc(
                Construct a CPUCryptoSystem with the specified security level (e.g. 128),
                message space 2^k, and a boolean for compact mode.

                Args:
                    security_level (int): The security level in bits.
                    k (int): The message space size (2^k).
                    compact (bool): Whether to use compact mode.

                Returns:
                    CPUCryptoSystem: The constructed cryptosystem.
            )pbdoc")
        .def("keygen",
             py::overload_cast<>(&CPUCryptoSystem::keygen, py::const_),
             R"pbdoc(
                Generate a fresh secret key.

                Returns:
                    SecretKey: The secret key.
            )pbdoc")
        .def("keygen",
             py::overload_cast<const SecretKey&>(&CPUCryptoSystem::keygen,
                                                 py::const_),
             py::arg("sk"),
             R"pbdoc(
                Generate a public key from a given secret key.

                Args:
                    sk (SecretKey): The secret key.

                Returns:
                    PublicKey: The public key.
            )pbdoc")
        .def("keygen",
             py::overload_cast<const SecretKey&, size_t, size_t>(
                 &CPUCryptoSystem::keygen, py::const_),
             py::arg("sk"), py::arg("threshold"), py::arg("num_parties"),
             R"pbdoc(
                Generate shares of a secret key (for threshold cryptography).

                Args:
                    sk (SecretKey): The secret key.
                    threshold (int): The threshold number of shares required to reconstruct the secret key.
                    num_parties (int): The total number of parties.

                Returns:
                    List[List[SecretKeyShare]]: The list of lists of secret key shares of each party for the threshold scheme.
            )pbdoc")
        .def("encrypt", &CPUCryptoSystem::encrypt, py::arg("pk"), py::arg("pt"),
             R"pbdoc(
                Encrypt a plaintext using the given public key.

                Args:
                    pk (PublicKey): The public key.
                    pt (PlainText): The plaintext. Must be in the message space.

                Returns:
                    CipherText: The ciphertext.
            )pbdoc")
        .def("encrypt_tensor", &CPUCryptoSystem::encrypt_tensor, py::arg("pk"),
             py::arg("pt_tensor"),
             R"pbdoc(
                Encrypt a tensor of plaintexts using the given public key.

                Args:
                    pk (PublicKey): The public key.
                    pt_tensor (Tensor[PlainText]): The tensor of plaintexts.

                Returns:
                    Tensor[CipherText]: The tensor of ciphertexts.
            )pbdoc")
        .def("decrypt", &CPUCryptoSystem::decrypt, py::arg("sk"), py::arg("ct"),
             R"pbdoc(
                Decrypt a ciphertext using the given secret key.

                Args:
                    sk (SecretKey): The secret key.
                    ct (CipherText): The ciphertext.

                Returns:
                    PlainText: The plaintext.
            )pbdoc")
        .def("decrypt_tensor", &CPUCryptoSystem::decrypt_tensor, py::arg("sk"),
             py::arg("ct_tensor"),
             R"pbdoc(
                Decrypt a tensor of ciphertexts using the given secret key.

                Args:
                    sk (SecretKey): The secret key.
                    ct_tensor (Tensor[CipherText]): The tensor of ciphertexts.

                Returns:
                    Tensor[PlainText]: The tensor of plaintexts.
            )pbdoc")
        .def("part_decrypt", &CPUCryptoSystem::part_decrypt, py::arg("sks"),
             py::arg("ct"),
             R"pbdoc(
                Perform partial decryption given a secret key share and ciphertext.

                Args:
                    sks (List[SecretKeyShare]): The list of secret key shares.
                    ct (CipherText): The ciphertext.

                Returns:
                    PartialDecryptionResult: The partial decryption result.
            )pbdoc")
        .def("part_decrypt_tensor", &CPUCryptoSystem::part_decrypt_tensor,
             py::arg("sks"), py::arg("ct_tensor"),
             R"pbdoc(
                Perform partial decryption on a tensor of ciphertexts.

                Args:
                    sks (List[SecretKeyShare]): The list of secret key shares.
                    ct_tensor (Tensor[CipherText]): The tensor of ciphertexts.

                Returns:
                    Tensor[PartialDecryptionResult]: The tensor of partial decryption results.
            )pbdoc")
        .def("combine_partial_decryption_results",
             &CPUCryptoSystem::combine_partial_decryption_results,
             py::arg("ct"), py::arg("pdrs"),
             R"pbdoc(
                Combine partial decryption results to recover the plaintext.

                Args:
                    ct (CipherText): The ciphertext.
                    pdrs (List[PartialDecryptionResult]): The list of partial decryption results.

                Returns:
                    PlainText: The plaintext.
            )pbdoc")
        .def("combine_partial_decryption_results_tensor",
             &CPUCryptoSystem::combine_partial_decryption_results_tensor,
             py::arg("ct"), py::arg("pdrs"),
             R"pbdoc(
                Combine partial decryption results on a tensor of ciphertexts.

                Args:
                    ct (CipherText): The ciphertext.
                    pdrs (List[Tensor[PartialDecryptionResult]]): The list of tensors of partial decryption results.

                Returns:
                    Tensor[PlainText]: The tensor of plaintexts.
            )pbdoc")
        .def("add_ciphertexts", &CPUCryptoSystem::add_ciphertexts,
             py::arg("pk"), py::arg("ct1"), py::arg("ct2"),
             R"pbdoc(
                Homomorphically add two ciphertexts under the given public key.

                Args:
                    pk (PublicKey): The public key.
                    ct1 (CipherText): The first ciphertext.
                    ct2 (CipherText): The second ciphertext.

                Returns:
                    CipherText: The resulting ciphertext.
            )pbdoc")
        .def("scal_ciphertext", &CPUCryptoSystem::scal_ciphertext,
             py::arg("pk"), py::arg("s"), py::arg("ct"),
             R"pbdoc(
                Scale (multiply) a ciphertext by a plaintext scalar.

                Args:
                    pk (PublicKey): The public key.
                    s (PlainText): The plaintext scalar.
                    ct (CipherText): The ciphertext.

                Returns:
                    CipherText: The resulting ciphertext.
            )pbdoc")
        .def("add_ciphertext_tensors", &CPUCryptoSystem::add_ciphertext_tensors,
             py::arg("pk"), py::arg("ct1"), py::arg("ct2"),
             R"pbdoc(
                Homomorphically add two tensors of ciphertexts.

                Args:
                    pk (PublicKey): The public key.
                    ct1 (Tensor[CipherText]): The first tensor of ciphertexts.
                    ct2 (Tensor[CipherText]): The second tensor of ciphertexts.

                Returns:
                    Tensor[CipherText]: The resulting tensor of ciphertexts.
            )pbdoc")
        .def("scal_ciphertext_tensors",
             &CPUCryptoSystem::scal_ciphertext_tensors, py::arg("pk"),
             py::arg("s"), py::arg("ct_tensor"),
             R"pbdoc(
                Scale (multiply) a tensor of ciphertexts by a plaintext scalar.

                Args:
                    pk (PublicKey): The public key.
                    s (PlainText): The plaintext scalar.
                    ct_tensor (Tensor[CipherText]): The tensor of ciphertexts.

                Returns:
                    Tensor[CipherText]: The resulting tensor of ciphertexts.
            )pbdoc")
        .def("add_plaintexts", &CPUCryptoSystem::add_plaintexts, py::arg("pt1"),
             py::arg("pt2"),
             R"pbdoc(
                Add two plaintexts.

                Args:
                    pt1 (PlainText): The first plaintext.
                    pt2 (PlainText): The second plaintext.

                Returns:
                    PlainText: The resulting plaintext.
            )pbdoc")
        .def("multiply_plaintexts", &CPUCryptoSystem::multiply_plaintexts,
             py::arg("pt1"), py::arg("pt2"),
             R"pbdoc(
                Multiply two plaintexts.

                Args:
                    pt1 (PlainText): The first plaintext.
                    pt2 (PlainText): The second plaintext.

                Returns:
                    PlainText: The resulting plaintext.
            )pbdoc")
        .def("add_plaintext_tensors", &CPUCryptoSystem::add_plaintext_tensors,
             py::arg("pt1"), py::arg("pt2"),
             R"pbdoc(
                Add two tensors of plaintexts.

                Args:
                    pt1 (Tensor[PlainText]): The first tensor of plaintexts.
                    pt2 (Tensor[PlainText]): The second tensor of plaintexts.

                Returns:
                    Tensor[PlainText]: The resulting tensor of plaintexts.
            )pbdoc")
        .def("multiply_plaintext_tensors",
             &CPUCryptoSystem::multiply_plaintext_tensors, py::arg("pt1"),
             py::arg("pt2"),
             R"pbdoc(
                Multiply two tensors of plaintexts.

                Args:
                    pt1 (Tensor[PlainText]): The first tensor of plaintexts.
                    pt2 (Tensor[PlainText]): The second tensor of plaintexts.

                Returns:
                    Tensor[PlainText]: The resulting tensor of plaintexts.
            )pbdoc")
        .def("negate_plaintext", &CPUCryptoSystem::negate_plaintext,
             py::arg("s"),
             R"pbdoc(
                Negate (multiply by -1) a plaintext.

                Args:
                    s (PlainText): The plaintext.

                Returns:
                    PlainText: The resulting
            )pbdoc")
        .def("negate_plaintext_tensor",
             &CPUCryptoSystem::negate_plaintext_tensor, py::arg("pt"),
             R"pbdoc(
                Negate (multiply by -1) a tensor of plaintexts.

                Args:
                    pt (Tensor[PlainText]): The tensor of plaintexts.

                Returns:
                    Tensor[PlainText]: The resulting tensor of plaintexts.
            )pbdoc")
        .def("negate_ciphertext", &CPUCryptoSystem::negate_ciphertext,
             py::arg("pk"), py::arg("ct"),
             R"pbdoc(
                Negate (multiply by -1) a ciphertext.

                Args:
                    pk (PublicKey): The public key.
                    ct (CipherText): The ciphertext.

                Returns:
                    CipherText: The resulting ciphertext, ie. the negation.
            )pbdoc")
        .def("negate_ciphertext_tensor",
             &CPUCryptoSystem::negate_ciphertext_tensor, py::arg("pk"),
             py::arg("ct"),
             R"pbdoc(
                Negate (multiply by -1) a tensor of ciphertexts.

                Args:
                    pk (PublicKey): The public key.
                    ct (Tensor[CipherText]): The tensor of ciphertexts.

                Returns:
                    Tensor[CipherText]: The resulting tensor of ciphertexts.
            )pbdoc")
        .def("make_plaintext", &CPUCryptoSystem::make_plaintext,
             py::arg("value"),
             R"pbdoc(
                Convert a float into the integer-based plaintext representation.

                Args:
                    value (float): The floating-point value.

                Returns:
                    PlainText: The plaintext corresponding to the value.
            )pbdoc")
        // required because functions expected Tensor<PlainText *> instead of
        // Tensor<PlainText>
        .def(
            "make_plaintext_tensor",
            [](CPUCryptoSystem& cs, const std::vector<size_t>& shape,
               const std::vector<float>& values) {
                size_t num_elements = 1;
                for (size_t i = 0; i < shape.size(); i++) {
                    num_elements *= shape[i];
                }
                if (num_elements != values.size()) {
                    throw std::invalid_argument(
                        "The number of values must match the size of the "
                        "tensor.");
                }
                Tensor<PlainText*> pts(num_elements, nullptr);
                for (size_t i = 0; i < values.size(); i++) {
                    pts[i] = new PlainText(cs.make_plaintext(values[i]));
                }
                pts.reshape(shape);
                return pts;
            },
            py::arg("shape"), py::arg("values"),
            R"pbdoc(
                Convert a list of floats into a tensor of plaintexts.

                Args:
                    shape (List[int]): The shape of the tensor.
                    values (List[float]): The list of floating-point values.

                Returns:
                    Tensor[PlainText]: The tensor of plaintexts corresponding to the values.
            )pbdoc")
        .def("get_float_from_plaintext",
             &CPUCryptoSystem::get_float_from_plaintext, py::arg("pt"),
             py::arg("scaling_factor") = 1, py::arg("depth") = 1,
             R"pbdoc(
                Convert a plaintext back into a floating-point approximation.

                Args:
                    pt (PlainText): The plaintext.
                    scaling_factor (int): The scaling factor.
                    depth (int): The depth.

                Returns:
                    float: The floating-point value.
            )pbdoc")
        .def(
            "get_float_from_plaintext_tensor",
            [](CPUCryptoSystem& cs, const Tensor<PlainText*>& pts,
               unsigned int scale_factor = 1, unsigned int depth = 1) {
                std::vector<float> values;
                auto flat_pts = pts;
                flat_pts.flatten();
                for (size_t i = 0; i < flat_pts.size(); i++) {
                    // values.push_back(cs.get_float_from_plaintext(*flat_pts.at(i),
                    // scale_factor, depth));
                    float val = cs.get_float_from_plaintext(
                        *flat_pts.at(i), scale_factor, depth);
                    if (std::isinf(val) || std::isnan(val)) {
                        throw std::runtime_error("Overflow detected for i=" +
                                                 std::to_string(i));
                    }
                    values.push_back(val);
                }
                return py::cast(values);
            },
            py::arg("pts"), py::arg("scale_factor") = 1, py::arg("depth") = 1,
            R"pbdoc(
                Convert a tensor of plaintexts back into a list of floating-point approximations.

                Args:
                    pts (Tensor[PlainText]): The tensor of plaintexts.

                Returns:
                    List[float]: The list of floating-point values.
            )pbdoc")
        .def("serialize", &CPUCryptoSystem::serialize,
             R"pbdoc(
                Serialize the cryptosystem object (including parameters).

                Returns:
                    str: The serialized object.
            )pbdoc")
        .def_static("deserialize", &CPUCryptoSystem::deserialize,
                    py::arg("data"),
                    R"pbdoc(
                Deserialize a CPUCryptoSystem instance from a string.

                Args:
                    data (str): The serialized object.

                Returns:
                    CPUCryptoSystem: The deserialized cryptosystem.
            )pbdoc")
        .def(
            "serialize_secret_key",
            [](CPUCryptoSystem& cs, const SecretKey& sk) {
                std::string data = cs.serialize_secret_key(sk);
                return py::bytes(data);
            },
            py::arg("sk"),
            R"pbdoc(
                Serialize a SecretKey into a string.

                Args:
                    sk (SecretKey): The secret key.

                Returns:
                    bytes: The serialized secret key.
            )pbdoc")
        .def(
            "deserialize_secret_key",
            [](CPUCryptoSystem& cs, const py::bytes& data) {
                std::string data_str = data;
                return cs.deserialize_secret_key(data_str);
            },
            py::arg("data"),
            R"pbdoc(
                Deserialize a SecretKey from a string.

                Args:
                    data (str): The serialized secret key.

                Returns:
                    SecretKey: The deserialized secret key.
            )pbdoc")
        .def(
            "serialize_public_key",
            [](CPUCryptoSystem& cs, const PublicKey& pk) {
                std::string data = cs.serialize_public_key(pk);
                return py::bytes(data);
            },
            py::arg("pk"),
            R"pbdoc(
                    Serialize a PublicKey into a bytes object.
            
                    Args:
                        pk (PublicKey): The public key.
            
                    Returns:
                        bytes: The serialized public key.
                )pbdoc")
        .def(
            "deserialize_public_key",
            [](CPUCryptoSystem& cs, const py::bytes& data) {
                std::string data_str = data;
                return cs.deserialize_public_key(data_str);
            },
            py::arg("data"),
            R"pbdoc(
                    Deserialize a PublicKey from a bytes object.
            
                    Args:
                        data (bytes): The serialized public key.
            
                    Returns:
                        PublicKey: The deserialized public key.
                )pbdoc")
        .def(
            "serialize_plaintext",
            [](CPUCryptoSystem& cs, const PlainText& pt) {
                std::string data = cs.serialize_plaintext(pt);
                return py::bytes(data);
            },
            py::arg("pt"),
            R"pbdoc(
                    Serialize a PlainText into a bytes object.
            
                    Args:
                        pt (PlainText): The plaintext.
            
                    Returns:
                        bytes: The serialized plaintext.
                )pbdoc")
        .def(
            "deserialize_plaintext",
            [](CPUCryptoSystem& cs, const py::bytes& data) {
                std::string data_str = data;
                return cs.deserialize_plaintext(data_str);
            },
            py::arg("data"),
            R"pbdoc(
                    Deserialize a PlainText from a bytes object.
            
                    Args:
                        data (bytes): The serialized plaintext.
            
                    Returns:
                        PlainText: The deserialized plaintext.
                )pbdoc")
        .def(
            "serialize_ciphertext",
            [](CPUCryptoSystem& cs, const CipherText& ct) {
                std::string data = cs.serialize_ciphertext(ct);
                return py::bytes(data);
            },
            py::arg("ct"),
            R"pbdoc(
                    Serialize a CipherText into a bytes object.
            
                    Args:
                        ct (CipherText): The ciphertext.
            
                    Returns:
                        bytes: The serialized ciphertext.
                )pbdoc")
        .def(
            "deserialize_ciphertext",
            [](CPUCryptoSystem& cs, const py::bytes& data) {
                std::string data_str = data;
                return cs.deserialize_ciphertext(data_str);
            },
            py::arg("data"),
            R"pbdoc(
                    Deserialize a CipherText from a bytes object.
            
                    Args:
                        data (bytes): The serialized ciphertext.
            
                    Returns:
                        CipherText: The deserialized ciphertext.
                )pbdoc")
        .def(
            "serialize_partial_decryption_result",
            [](CPUCryptoSystem& cs, const PartialDecryptionResult& pdr) {
                std::string data = cs.serialize_partial_decryption_result(pdr);
                return py::bytes(data);
            },
            py::arg("pdr"),
            R"pbdoc(
                    Serialize a PartialDecryptionResult into a bytes object.
            
                    Args:
                        pdr (PartialDecryptionResult): The partial decryption result.
            
                    Returns:
                        bytes: The serialized partial decryption result.
                )pbdoc")
        .def(
            "deserialize_partial_decryption_result",
            [](CPUCryptoSystem& cs, const py::bytes& data) {
                std::string data_str = data;
                return cs.deserialize_partial_decryption_result(data_str);
            },
            py::arg("data"),
            R"pbdoc(
                    Deserialize a PartialDecryptionResult from a bytes object.
            
                    Args:
                        data (bytes): The serialized partial decryption result.
            
                    Returns:
                        PartialDecryptionResult: The deserialized partial decryption result.
                )pbdoc")
        .def(
            "serialize_secret_key_share",
            [](CPUCryptoSystem& cs, const SecretKeyShare& sks) {
                std::string data = cs.serialize_secret_key_share(sks);
                return py::bytes(data);
            },
            py::arg("sks"),
            R"pbdoc(
                    Serialize a SecretKeyShare into a bytes object.
            
                    Args:
                        sks (SecretKeyShare): The secret key share.
            
                    Returns:
                        bytes: The serialized secret key share.
                )pbdoc")
        .def(
            "deserialize_secret_key_share",
            [](CPUCryptoSystem& cs, const py::bytes& data) {
                std::string data_str = data;
                return cs.deserialize_secret_key_share(data_str);
            },
            py::arg("data"),
            R"pbdoc(
                    Deserialize a SecretKeyShare from a bytes object.
            
                    Args:
                        data (bytes): The serialized secret key share.
            
                    Returns:
                        SecretKeyShare: The deserialized secret key share.
                )pbdoc")
        .def(
            "serialize_plaintext_tensor",
            [](CPUCryptoSystem& cs, const Tensor<PlainText*>& pt_tensor) {
                std::string data = cs.serialize_plaintext_tensor(pt_tensor);
                return py::bytes(data);
            },
            py::arg("pt_tensor"),
            R"pbdoc(
                Serialize a tensor of PlainTexts into a bytes object.

                Args:
                    pt_tensor (Tensor[PlainText]): The tensor of plaintexts.

                Returns:
                    bytes: The serialized tensor of plaintexts
            )pbdoc")
        .def(
            "deserialize_plaintext_tensor",
            [](CPUCryptoSystem& cs, const py::bytes& data) {
                std::string data_str = data;
                return cs.deserialize_plaintext_tensor(data_str);
            },
            py::arg("data"),
            R"pbdoc(
                Deserialize a tensor of PlainTexts from a bytes object.

                Args:
                    data (bytes): The serialized tensor of plaintexts.

                Returns:
                    Tensor[PlainText]: The deserialized tensor of plaintexts.
            )pbdoc")
        .def(
            "serialize_ciphertext_tensor",
            [](CPUCryptoSystem& cs, const Tensor<CipherText*>& ct_tensor) {
                std::string data = cs.serialize_ciphertext_tensor(ct_tensor);
                return py::bytes(data);
            },
            py::arg("ct_tensor"),
            R"pbdoc(
                Serialize a tensor of CipherTexts into a bytes object.

                Args:
                    ct_tensor (Tensor[CipherText]): The tensor of ciphertexts.

                Returns:
                    bytes: The serialized tensor of ciphertexts.
            )pbdoc")
        .def(
            "deserialize_ciphertext_tensor",
            [](CPUCryptoSystem& cs, const py::bytes& data) {
                std::string data_str = data;
                return cs.deserialize_ciphertext_tensor(data_str);
            },
            py::arg("data"),
            R"pbdoc(
                Deserialize a tensor of CipherTexts from a bytes object.

                Args:
                    data (bytes): The serialized tensor of ciphertexts.

                Returns:
                    Tensor[CipherText]: The deserialized tensor of ciphertexts.
            )pbdoc")
        .def(
            "serialize_partial_decryption_result_tensor",
            [](CPUCryptoSystem& cs,
               const Tensor<PartialDecryptionResult*>& pdr_tensor) {
                std::string data =
                    cs.serialize_partial_decryption_result_tensor(pdr_tensor);
                return py::bytes(data);
            },
            py::arg("pdr_tensor"),
            R"pbdoc(
                Serialize a tensor of PartDecryptionResults into a bytes object.

                Args:
                    pdr_tensor (Tensor[PartialDecryptionResult]): The tensor of partial decryption results.

                Returns:
                    bytes: The serialized tensor of partial decryption results.
            )pbdoc")
        .def(
            "deserialize_partial_decryption_result_tensor",
            [](CPUCryptoSystem& cs, const py::bytes& data) {
                std::string data_str = data;
                return cs.deserialize_partial_decryption_result_tensor(
                    data_str);
            },
            py::arg("data"),
            R"pbdoc(
                Deserialize a tensor of PartDecryptionResults from a bytes object.

                Args:
                    data (bytes): The serialized tensor of partial decryption results.

                Returns:
                    Tensor[PartialDecryptionResult]: The deserialized tensor of partial decryption results.
            )pbdoc")
        .def(
            "get_ciphertexts_from_ciphertext_tensor",
            [](CPUCryptoSystem& cs, const Tensor<CipherText*>& ct_tensor) {
                std::vector<CipherText> cts;
                auto flat_cts = ct_tensor;
                flat_cts.flatten();
                for (size_t i = 0; i < flat_cts.size(); i++) {
                    cts.push_back(*flat_cts[i]);
                }
                return cts;
            },
            py::arg("ct_tensor"),
            R"pbdoc(
                    Serialize a tensor of CipherTexts into a string.

                    Args:
                        ct_tensor (Tensor[CipherText]): The tensor of ciphertexts.

                    Returns:
                        List[CipherText]: The list of ciphertexts.
                )pbdoc");
}