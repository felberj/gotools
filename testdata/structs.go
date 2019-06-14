package main

import "fmt"

type AStruct struct {
	PublicField  int
	privateField int
}

func (a *AStruct) GetPub() int {
	return a.PublicField
}

func (a *AStruct) GetPriv() int {
	return a.privateField
}

func Create() *AStruct {
	return &AStruct{
		PublicField:  0xaaaa,
		privateField: 0xbbbb,
	}
}

func main() {
	a := Create()
	fmt.Println("%d %d", a.GetPriv(), a.privateField)
}
