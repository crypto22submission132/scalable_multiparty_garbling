# Scalable Multiparty Garbling


## Dependencies
The benchmarks are implemented in C++17 and Python 3, both of which need to be available to estimate the performance.
[CMake](https://cmake.org/) is used as the C++ build system.

The following libraries need to be installed separately and should be available to the build system and compiler.

- [GMP](https://gmplib.org/)
- [NTL](https://www.shoup.net/ntl/) (11.0.0 or later)
- [Boost](https://www.boost.org/) (1.78.0 or later)
- [Nlohmann JSON](https://github.com/nlohmann/json)
- [EMP Tool](https://github.com/emp-toolkit/emp-tool)

Additionally, [numpy](https://numpy.org/) should be available to the Python interpreter.

## Compilation
The project uses [CMake](https://cmake.org/) for building the source code. 
To compile, run the following commands from the root directory of the repository:

```sh
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..

# The two main targets are 'microbenchmarks' and 'tests' corresponding to
# binaries used to run microbenchmarks and unit tests respectively.
make <target>
```

## Usage
We give an example of how to run the program by estimating the runtime of the protocol for the AES-128 circuit.

```sh
# Create a directory to store output.
mkdir data

# The AES-128 circuit has 6400 AND gates and 30263 XOR gates.
g_and=6400
g_xor=30263

# We consider 150 parties with a corruption threshold of 37.
num_parties=150
threshold=37

# Use the python script to compute the number of bits communicated by each 
# party in every round and store the output in the 'data/comm_val' directory.
python ./microbenchmarks/communication.py -o ./data/comm_val $num_parties $threshold $g_and $g_xor

# Compute microbenchmarks for computation.
./build/microbenchmarks/add_gf2e -o ./data
./build/microbenchmarks/mult_gf2e -o ./data
./build/microbenchmarks/ecc_gf2e -o ./data
./build/microbenchmarks/precon_gf2e --num_parties $num_parties --threshold $threshold -o ./data

# Compute communication timings.
./scripts/run_parties.sh $num_parties ./data/comm_val ./data/comm_time

# Put together computation benchmarks for total computation time for protocol.
python ./microbenchmarks/computation.py $num_parties $threshold ./data $g_and $g_xor

# Compute the average across the communication timings for each party.
python ./scripts/average_communication.py $num_parties ./data/comm_time

# Adding up the values output from the last two commands will give the total running time of the algorithm.
```
