#!/bin/bash
set -e 

# Print test header
announce(){
  title="#    $1    #"
  edge=$(echo "$title" | sed 's/./#/g')
  echo -e "\n\n$edge"; echo "$title"; echo "$edge";
}

MODE=("mode2" "mode3" "mode5")

for mode in ${MODE[@]}; do
  announce "Dilithium $mode"
  cargo test --features "$mode KAT"

  announce "Dilithium $mode AES"
  cargo test --features "$mode aes KAT"

  announce "Dilithium $mode Random Signing"
  cargo test --features "$mode random_signing"
done


