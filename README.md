Go Plugin for Ghidra
=============================

Plugin to assist reversing Golang binaries with Ghidra.

This is in a VERY early stage and for now only handles linux/x86_64 binaries.


# Features

- Recover function names
- Recover number of arguments and return type

# References

- (Reversing GO binaries like a pro)[https://rednaga.io/2016/09/21/reversing_go_binaries_like_a_pro/]
- (pkg/runtime documentation)[https://golang.org/pkg/runtime/]
- (The Go low-level calling convention on x86-64)[https://science.raphael.poss.name/go-calling-convention-x86-64.html#strings-and-slices-use-two-and-three-words]
