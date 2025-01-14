#include <sstream>
#include <string>
#include <vector>

#include <pybind11/functional.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "cofhe.hpp"

template <typename T>
void init_tensor_class_bindings(pybind11::module_& m,
                                const std::string& class_name) {
    using namespace CoFHE;
    using Tensor = Tensor<T>;

    namespace py = pybind11;

    py::class_<Tensor>(m, class_name.c_str())
        .def(py::init<T>(), py::arg("value"),
             R"pbdoc(
        Construct a 0-dimensional tensor with the given value.

        Args:
            value (T): The value of the tensor.

        Returns:
            Tensor: A 0-dimensional tensor.
        )pbdoc")
        .def(py::init<std::vector<size_t>, T>(), py::arg("shape"),
             py::arg("value"),
             R"pbdoc(
        Construct a tensor with the given shape and value.

        Args:
            shape (List[int]): The shape of the tensor.
            value (T): The value of the tensor.

        Returns:
            Tensor: A tensor with the given shape and value.
        )pbdoc")
        .def(py::init<size_t, T>(), py::arg("n"), py::arg("value"),
             R"pbdoc(
        Construct a 1-dimensional tensor with the given value.

        Args:
            n (int): The size of the tensor.
            value (T): The value of the tensor.

        Returns:
            Tensor: A 1-dimensional tensor.
        )pbdoc")
        .def(py::init<size_t, size_t, T>(), py::arg("n"), py::arg("m"),
             py::arg("value"),
             R"pbdoc(
        Construct a 2-dimensional tensor with the given value.

        Args:
            n (int): The number of rows of the tensor.
            m (int): The number of columns of the tensor.
            value (T): The value of the tensor.

        Returns:
            Tensor: A 2-dimensional tensor.
        )pbdoc")
        .def(py::init<std::vector<size_t>, std::vector<T>>(), py::arg("shape"),
             py::arg("values"),
             R"pbdoc(
        Construct a tensor with the given shape and values.

        Args:
            shape (List[int]): The shape of the tensor.
            values (List[T]): The values of the tensor.

        Returns:
            Tensor: A tensor with the given shape and values.
        )pbdoc")
        .def_property_readonly("shape",
                               py::overload_cast<>(&Tensor::shape, py::const_),
                               R"pbdoc(
        The shape of the tensor.

        Returns:
            List[int]: The shape of the tensor.
        )pbdoc")
        .def_property_readonly("size", &Tensor::num_elements,
                               R"pbdoc(
        The number of elements in the tensor.

        Returns:
            int: The number of elements in the tensor.
        )pbdoc")
        .def_property_readonly("ndim", &Tensor::ndim,
                               R"pbdoc(

        Returns:
            int: The number of dimensions of the tensor.
        )pbdoc")
        .def_property_readonly("is_scalar", &Tensor::is_zero_degree,
                               R"pbdoc(
        Whether the tensor is a scalar.

        Returns:
            bool: Whether the tensor is a scalar.
        )pbdoc")
        .def_property_readonly("is_vector", &Tensor::is_column_vector,
                               R"pbdoc(
        Whether the tensor is a vector.

        Returns:
            bool: Whether the tensor is a vector.
        )pbdoc")
        .def_property_readonly("is_matrix", &Tensor::is_2d_matrix,
                               R"pbdoc(
        Whether the tensor is a matrix.

        Returns:
            bool: Whether the tensor is a matrix.
        )pbdoc")
        .def_property_readonly("is_contiguous", &Tensor::is_contiguous,
                               R"pbdoc(
        Whether the tensor is contiguous.

        Returns:
            bool: Whether the tensor is contiguous.
        )pbdoc")
        .def("__getitem__", py::overload_cast<size_t>(&Tensor::at, py::const_),
             py::arg("index"),
             R"pbdoc(
        Get the element at the given index.

        Returns:
            T: The element at the given index.
        )pbdoc")
        .def("__getitem__",
             py::overload_cast<const std::vector<size_t>&>(&Tensor::at,
                                                           py::const_),
             py::arg("indices"),
             R"pbdoc(
        Get the element at the given indices.

        Returns:
            T: The element at the given indices.

        Example:
            >>> t = Tensor([2, 2], [1, 2, 3, 4])
            >>> t[[0, 1]]
            2
        )pbdoc")
        .def(
            "__setitem__",
            [](Tensor& t, size_t index, T value) { t.at(index) = value; },
            py::arg("index"), py::arg("value"),
            R"pbdoc(
        Set the element at the given index.

        Args:
            index (int): The index of the element.
            value (T): The value of the element.
        )pbdoc")
        .def(
            "__setitem__",
            [](Tensor& t, const std::vector<size_t>& indices, T value) {
                t.at(indices) = value;
            },
            py::arg("indices"), py::arg("value"),
            R"pbdoc(
        Set the element at the given indices.

        Args:
            indices (List[int]): The indices of the element.
            value (T): The value of the element.

        Example:
            >>> t = Tensor([2, 2], [1, 2, 3, 4])
            >>> t[[0, 1]] = 5
            >>> t
            Tensor([2, 2], [1, 5, 3, 4])
        )pbdoc")
        .def("__str__",
             [](Tensor& t) {
                 std::stringstream ss;
                 t.print(ss);
                 return ss.str();
             })
        .def(
            "flatten",
            [](Tensor& t) {
                auto t_ = t;
                t_.flatten();

                return t_;
            },
            R"pbdoc(
        Flatten the tensor.

        Returns:
            Tensor: The flattened tensor.
            )pbdoc")
        .def(
            "reshape",
            [](Tensor& t, std::vector<size_t> shape) {
                auto t_ = t;
                t_.reshape(shape);
                return t_;
            },
            py::arg("shape"),
            R"pbdoc(
        Reshape the tensor.

        Args:
            shape (List[int]): The new shape of the tensor.

        Returns:
            Tensor: The reshaped tensor.
        )pbdoc")
        .def("make_contiguous", &Tensor::make_contiguous,
             R"pbdoc(
        Make the tensor contiguous.
        )pbdoc");
}