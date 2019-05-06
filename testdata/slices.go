package main

/*
    undefined8	<RETURN>	Stack[0x20]:8
1	/GoSlice    Unaligned
Structure GoSlice {
}
Size = 24   Actual Alignment = 1
	slice	Stack[0x8]:24
*/
func getLen(a []int) int {
	return len(a)
}

func getFirst(a []int) int {
	return a[0]
}

func get(a []int, x int) int {
	return a[x]
}

func getCap(a []int) int {
	return cap(a)
}

func createSlice() []int {
	return []int{1, 2, 3, 4, 5, 6, 7}
}

func main() {
	a := createSlice()
	l := getLen(a)
	f := getFirst(a)
	e := get(a, 3)
	c := getCap(a)

	_ = l + f + e + c
}
