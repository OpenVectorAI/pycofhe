#include "tensor/tensor_pyb.hpp"

PYBIND11_MODULE(tensor_core, m) {
    m.doc() = "Python binding for CoFHE tensor";

    init_tensor_class_bindings<double>(m, "Tensor");
    init_tensor_class_bindings<int>(m, "IntTensor");
}