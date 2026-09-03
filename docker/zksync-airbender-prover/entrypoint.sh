#!/bin/sh

ulimit -s 300000
exec /usr/bin/zksync-airbender-prover "$@"
