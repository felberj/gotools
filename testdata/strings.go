package main

func ReturnString() string {
	return "Hello World"
}

func AppendString(a, b string) string {
	return a + b
}

func ToSlice(s string) []byte {
	return []byte(s)
}

func FromSlice(s []byte) string {
	return string(s)
}

func Len(s string) int {
	return len(s)
}

func main() {
	a := ReturnString()
	b := ReturnString()
	_ = AppendString(a, b)
	by := ToSlice("Hallo Welt")
	_ = FromSlice(by)
}
