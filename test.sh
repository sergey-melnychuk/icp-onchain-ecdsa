#!/bin/sh

msg=test
echo " msg: $msg"
hash=$(printf $msg | shasum -a 256 | cut -d' ' -f 1)
echo "hash: $hash"

pkey=$(dfx canister call signer pkey "vec { 123; 456; 789 }" | grep Ok | cut -d'=' -f 2 | cut -d'"' -f 2)
echo "pkey: $pkey"

sig=$(dfx canister call signer sign "(vec { 123; 456; 789 }, \"$hash\")"  | grep Ok | cut -d'=' -f 2 | cut -d'"' -f 2)
echo " sig: $sig"

cargo build --examples 2> /dev/null > /dev/null
./target/debug/examples/verify $msg $sig $pkey
