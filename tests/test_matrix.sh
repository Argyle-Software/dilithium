#!/bin/bash
set -e 

# Print test header
announce(){
  title="#    $1    #"
  edge=$(echo "$title" | sed 's/./#/g')
  echo -e "\n\n$edge"; echo "$title"; echo "$edge";
}

# Keep existing RUSTFLAGS
RUSTFLAGS=${RUSTFLAGS:-""}
RUSTFLAGS+=" --cfg dilithium_kat"

MODE=("mode2" "mode3" "mode5")

for mode in ${MODE[@]}; do
  announce "Dilithium $mode"
  RUSTFLAGS=$RUSTFLAGS cargo test --features "$mode"

  announce "Dilithium $mode AES"
  RUSTFLAGS=$RUSTFLAGS cargo test --features "$mode aes"

  announce "Dilithium $mode Random Signing"
  RUSTFLAGS=$RUSTFLAGS cargo test --features "$mode random_signing"
done
