package main

type mode int
const (
	modeEncrypt mode = iota
	modeDecrypt
)

type method int
const (
	methodSimple method = iota
	methodPiecewise
)

// parameters is used to convey command line
// options to the main function
type parameters struct {
	mode                               mode
	method                             method
	infile, outfile, credfile, profile string
}
