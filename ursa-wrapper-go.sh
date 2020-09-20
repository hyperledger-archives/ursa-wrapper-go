#!/bin/bash

PWD=$(pwd)
export URSA_GO_ROOT=$PWD
export PATH=$PWD/bin:$PATH

export CGO_CFLAGS=-I"${URSA_GO_ROOT}"/include