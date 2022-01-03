
[![GoDoc](https://godoc.org/github.com/mhe/gabi?status.svg)](https://godoc.org/github.com/mhe/gabi) [![Build Status](https://travis-ci.org/mhe/gabi.svg?branch=master)](https://travis-ci.org/mhe/gabi)

Status
------

This version of gabi is **UNMAINTAINED**, do not use. Development has continued at the [Privacy by Design foundation](https://privacybydesign.foundation/), more specifically [here](https://github.com/privacybydesign/gabi/).

Gabi
====

Gabi is a Go implementation of the [IRMA](https://www.irmacard.org) approach to the [Idemix](http://www.research.ibm.com/labs/zurich/idemix/) attribute based credential system. Check out the [IRMA](https://privacybydesign.foundation/irma) website to learn more on this great alternative to traditional identity management. 

gabi itself is designed to be compatible with the existing [Java](https://github.com/credentials/credentials_idemix) and [C++](https://github.com/credentials/silvia) implementations of the IRMA system.



Install
-------

To install:

    go get -v github.com/mhe/gabi

Test
----

To run tests:

    go test -v ./... 

