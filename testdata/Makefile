all: strings slices

slices: slices.go
	GOOS=linux go build -gcflags '-N -l' slices.go

strings: strings.go
	GOOS=linux go build -gcflags '-N -l' strings.go

