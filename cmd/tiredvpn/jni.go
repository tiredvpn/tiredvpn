// +build android

package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"os"
	"strings"
	"unsafe"
)

//export RunClient
func RunClient(argc C.int, argv **C.char) C.int {
	// Convert C argv to Go []string
	args := make([]string, 0, int(argc))
	argvSlice := unsafe.Slice(argv, argc)
	for i := 0; i < int(argc); i++ {
		args = append(args, C.GoString(argvSlice[i]))
	}

	// Set os.Args for compatibility with existing flag parsing
	os.Args = args

	// Check if we have "client" command
	if len(args) < 2 {
		return 1
	}

	// Strip "client" if it's the first arg (after binary name)
	if args[1] == "client" {
		runClient(args[2:])
	} else {
		runClient(args[1:])
	}

	return 0
}

//export RunClientArgs
func RunClientArgs(argsStr *C.char) C.int {
	// Parse space-separated args string
	argsString := C.GoString(argsStr)
	args := strings.Fields(argsString)

	// Prepend binary name
	args = append([]string{"tiredvpn"}, args...)

	// Set os.Args for compatibility with existing flag parsing
	os.Args = args

	// Run client with parsed args
	runClient(args[1:])

	return 0
}
