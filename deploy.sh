#!/bin/bash

### Setup docker operations. See build/common.sh for details.
source ${PWD}/build/common.sh && do_docker && do_deploy && exit $?
