all: strings slices structs functions

slices: slices.go
	GOOS=linux go build -gcflags '-N -l' slices.go

strings: strings.go
	GOOS=linux go build -gcflags '-N -l' strings.go

structs: structs.go
	GOOS=linux go build -gcflags '-N -l' structs.go


functions: functions.go
	GOOS=linux go build -gcflags '-N -l' functions.go
