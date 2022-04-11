num_parties=$1
inp=$2
out=$3

mkdir $out

for i in `seq 1 1 $(( num_parties - 1 ))`
do
    ./build/microbenchmarks/comm_runner --party $i --input $inp --output $out --repeat 5 >/dev/null 2>&1 &
done

./build/microbenchmarks/comm_runner --party 0 --input $inp --output $out --repeat 5
