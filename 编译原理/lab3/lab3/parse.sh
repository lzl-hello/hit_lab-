mkdir -p out2
file_name=$(basename $1)
./Code/parser $1 ./out2/${file_name}.ir
