// Copyright 2020 Ubiq Security, Inc., Proprietary and All Rights Reserved.
//
// NOTICE:  All information contained herein is, and remains the property
// of Ubiq Security, Inc. The intellectual and technical concepts contained
// herein are proprietary to Ubiq Security, Inc. and its suppliers and may be
// covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law. Dissemination of this
// information or reproduction of this material is strictly forbidden
// unless prior written permission is obtained from Ubiq Security, Inc.
//
// Your use of the software is expressly conditioned upon the terms
// and conditions available at:
//
//     https://ubiqsecurity.com/legal

package main

import (
	"fmt"
	"gitlab.com/ubiqsecurity/ubiq-go"
	"os"
)

func _main(params parameters) error {
	// new credentials
	credentials, err :=
		ubiq.NewCredentials(
			params.credfile, params.profile)
	if err != nil {
		return err
	}

	// open the input file
	ifp, err := os.Open(params.infile)
	if err != nil {
		return err
	}
	defer ifp.Close()

	// determine the size of the input file
	size, _ := ifp.Seek(0, os.SEEK_END)
	ifp.Seek(0, os.SEEK_SET)

	// don't allow the simple method if the
	// input file is too large
	if params.method == methodSimple &&
		size > maxSimpleSize {
		fmt.Fprintf(os.Stderr, "NOTE: This is only for demonstration purposes and is designed to work on memory\n")
		fmt.Fprintf(os.Stderr, "      constrained devices.  Therefore, this sample application will switch to\n")
		fmt.Fprintf(os.Stderr, "      the piecewise APIs for files larger than %u bytes in order to reduce\n", maxSimpleSize)
		fmt.Fprintf(os.Stderr, "      excesive resource usages on resource constrained IoT devices\n")
		params.method = maxSimpleSize
	}

	// create the output file
	ofp, err := os.Create(params.outfile)
	if err != nil {
		return err
	}
	defer ofp.Close()

	// encrypt or decrypt using the specified method
	if params.method == methodSimple {
		if params.mode == modeEncrypt {
			err = simpleEncrypt(credentials, ifp, ofp, size)
		} else /* decrypt */ {
			err = simpleDecrypt(credentials, ifp, ofp, size)
		}
	} else /* piecewise */ {
		if params.mode == modeEncrypt {
			err = piecewiseEncrypt(credentials, ifp, ofp)
		} else /* decrypt */ {
			err = piecewiseDecrypt(credentials, ifp, ofp)
		}
	}

	return err
}

func main() {
	// os.Exit immediately exits the program without running
	// any deferred functions. therefore, the main functionality
	// is located in the _main function, allowing deferred
	// functions to run prior to returning. os.Exit is then
	// called from this function in response to any errors
	err := _main(getopts())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(exitFailure)
	}
}
