Go Plugin for Ghidra
=============================

Plugin to assist reversing Golang binaries with Ghidra.

This is in a VERY early stage and for now only handles linux/x86_64 binaries.

# Usage

When importing, select the Language **x86:LE:64:golang:default**

# Features

- Recover function names
- Recover number of arguments and return type

# Developers

Code formatted with

`clang-format -i -style=Google src/main/java/gotools/*.java`

# References

- [Reversing GO binaries like a pro](https://rednaga.io/2016/09/21/reversing_go_binaries_like_a_pro/)
- [pkg/runtime documentation](https://golang.org/pkg/runtime/)
- [The Go low-level calling convention on x86-64](https://science.raphael.poss.name/go-calling-convention-x86-64.html#strings-and-slices-use-two-and-three-words)
