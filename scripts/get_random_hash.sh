for i in 1 2 3 4 5; do
  index=$((RANDOM * 10000 % 15_385_139))
  offset=$((index * 96))
  echo "Entry $i (offset $offset):"
  dd if=/Volumes/Bitcoin/pir/utxo_chunks_cuckoo.bin bs=1 skip=$offset count=20 2>/dev/null | xxd -p | tr -d '\n'
done