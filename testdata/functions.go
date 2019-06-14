package main

import (
	"fmt"
	"os"
)

func main() {
	A0r0()
	A1r0(0)
	A4r0(0, 1, 2, 3)
	one := A0r1()
	a, b, c, d := A0r4()
	e, f := A2r2(0, 1)

	if a+b+c+d+e+f+one == 0 {
		os.Exit(1)
	}
	os.Exit(2)
}

func A0r0() {
	fmt.Println("A0r0")
}

func A1r0(a int) {
	fmt.Println("A1r0", a)
}

func A0r1() int {
	fmt.Println("A0r1")
	return 0xaaaa
}

func A4r0(a, b, c, d int) {
	fmt.Println("A4r0", a, b, c, d)
}

func A0r4() (int, int, int, int) {
	fmt.Println("A0R4")
	return 1, 2, 3, 4
}

func A2r2(a, b int) (int, int) {
	fmt.Println("A2R2", a, b)
	return 1, 2
}
