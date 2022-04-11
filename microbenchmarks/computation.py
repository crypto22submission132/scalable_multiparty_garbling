import math
import numpy as np
import argparse
import json
import os


class Params:
    # To be given as input
    n = 200  # number of parties
    t = 50  # corruption threshold

    stat_sec = 40  # statistical security parameter
    comp_sec = 128  # computational security parameter

    MCheck_k = 20  # number of rounds for malcious check

    G_and, G_xor = (1000, 1000)  # circuit parameters
    HashLen = 256  # length of hash (bits)
    F_len = 8  # size of element in field (bits)

    # Computed from above
    l = 5  # number of packed secret sharing slots
    Q, V = (3600, 1275)  # LPN parameters (Q = ciphertext length, V = length of key)
    binH_k = 1  # binary HIM output dim i.e., Binary HIM order is (k x n)

    @staticmethod
    def initialize():
        Params.l = int(math.floor(Params.n / 4 - Params.t / 2))
        if Params.l < 1:
            raise Exception(f"Corruption threshold too low ({Params.t})")

        if Params.G_and == 0 and Params.G_xor == 0:
            raise Exception(f"Need non-empty circuit.")

        params = Params.find_BCH_RS(Params.n)
        if params == None:
            raise Exception("No BCH RS params found")
        _, k_RS, _, _, k_bin, _ = params
        Params.binH_k = int(k_RS * k_bin)

    @staticmethod
    def check_RS(N, n_bin, k_bin, d_bin):
        n_RS = (N + n_bin - 1) // n_bin
        if n_RS > 2**k_bin:
            return False

        d_RS = (n_RS * n_bin + 3 * d_bin - 1) // (3 * d_bin)

        if d_RS > n_RS:
            return False

        k_RS = n_RS - d_RS + 1
        return (n_RS, k_RS, d_RS)

    @staticmethod
    def find_BCH_RS(N):
        best_params = None
        best_k = 0
        for m in range(1, 11):
            n_bin = 2**m - 1
            t_max = n_bin // m
            for t in np.arange(t_max, 0, -1):
                k_bin = n_bin - m * t
                if k_bin <= 1:
                    continue
                d_bin = 2 * t + 1
                if d_bin < n_bin // 3:
                    break

                check = Params.check_RS(N, n_bin + 1, k_bin, d_bin + 1)

                if check != False:
                    n_RS, k_RS, d_RS = check
                    k = k_RS * k_bin
                    if k > best_k:
                        best_k = k
                        best_params = (n_RS, k_RS, d_RS, n_bin + 1, k_bin, d_bin + 1)

        return best_params


class State:
    def __init__(self):
        self.num_prand = {}
        self.num_dprand = {}
        self.num_triples = 0
        self.iprod = []

    def new_prand(self, num, field_len):
        self.num_prand[field_len] = self.num_prand.get(field_len, 0) + num

    def new_dprand(self, num, field_len):
        self.num_dprand[field_len] = self.num_dprand.get(field_len, 0) + num

    def add_triples(self, num):
        self.num_triples += num

    def add_iprod(self, inp_len_list):
        self.iprod.extend(inp_len_list)


class Timer:
    def __init__(self, data_dir, threads):
        self.stats = {
            Params.F_len: {"add": 1, "mult": 10, "precon": 12},
            "ecc": 100,
        }
        self.round = {}
        self.time = {"add": 0, "mult": 0, "precon": 0, "ecc": 0}
        self.num = {"add": 0, "mult": 0, "precon": 0, "ecc": 0}

        # Load timing info from computed microbenchmarks.
        self.stats[Params.F_len]["add"] = Timer.load_time(
            os.path.join(data_dir, f"addgf2e_d{Params.F_len}_t{threads}.json")
        )

        self.stats[Params.F_len]["mult"] = Timer.load_time(
            os.path.join(data_dir, f"multgf2e_d{Params.F_len}_t{threads}.json")
        )

        self.stats[Params.F_len]["precon"] = Timer.load_time(
            os.path.join(
                data_dir,
                f"precongf2e_n{Params.n}_t{Params.t}_d{Params.F_len}_t{threads}.json",
            )
        )

        self.stats["ecc"] = Timer.load_time(
            os.path.join(
                data_dir,
                f"ecc_d{Params.F_len}_m{Params.V + 1}_c{Params.Q}_t{threads}.json",
            )
        )

    @staticmethod
    def load_time(fpath):
        with open(fpath, "r") as f:
            data = json.load(f)

        return sum(data["stats"]) / (len(data["stats"]) * data["details"]["num"])

    def add(self, rid, num, field_len):
        t = self.stats[field_len]["add"] * num
        self.round[rid] = self.round.get(rid, 0) + t
        self.time["add"] += t
        self.num["add"] += num
        return t

    def mult(self, rid, num, field_len):
        t = self.stats[field_len]["mult"] * num
        self.round[rid] = self.round.get(rid, 0) + t
        self.time["mult"] += t
        self.num["mult"] += num
        return t

    def precon(self, rid, num, field_len):
        t = self.stats[field_len]["precon"] * num
        self.round[rid] = self.round.get(rid, 0) + t
        self.time["precon"] += t
        self.num["precon"] += num
        return t

    def ecc(self, rid, num):
        t = self.stats["ecc"] * num
        self.round[rid] = self.round.get(rid, 0) + t
        self.time["ecc"] += t
        self.num["ecc"] += num
        return t


class Multiplier:
    time = 0

    def __init__(self, timer, state, robust=True):
        self.timer = timer
        self.state = state
        self.robust = robust

    def run(self, rid, num, field_len):
        # Compute masked shares.
        self.time += self.timer.mult(rid, num, field_len)
        Multiplier.time += self.timer.add(rid, num, field_len)
        rid += 1

        # Reconstruct and unmask shares.
        Multiplier.time += self.timer.precon(rid, num, field_len)
        Multiplier.time += self.timer.add(rid, num, field_len)
        rid += 1

        if self.robust:
            self.state.add_triples(num)
        self.state.new_dprand(num, field_len)
        return rid


class InnerProduct:
    time = 0

    def __init__(self, timer, state, robust=True):
        self.timer = timer
        self.state = state
        self.robust = robust

    def run(self, rid, inp_len_list, field_len):
        num = len(inp_len_list)

        # Compute inner products.
        InnerProduct.time += self.timer.mult(rid, sum(inp_len_list), field_len)
        InnerProduct.time += self.timer.add(rid, sum(inp_len_list), field_len)

        # Mask shares
        InnerProduct.time += self.timer.add(rid, num, field_len)
        rid += 1

        # Reconstruct and unmask shares.
        InnerProduct.time += self.timer.precon(rid, num, field_len)
        InnerProduct.time += self.timer.add(rid, num, field_len)
        rid += 1

        if self.robust:
            self.state.add_iprod(inp_len_list)
        self.state.new_dprand(len(inp_len_list), field_len)
        return rid


class PackRecon:
    time = 0

    def __init__(self, timer):
        self.timer = timer

    def run(self, rid, num, field_len):
        PackRecon.time += self.timer.precon(rid, num, field_len)
        return rid + 1


class MaliciousCheckProd:
    def __init__(self, timer, state):
        self.timer = timer
        self.state = state
        self.mult = Multiplier(timer, state, False)
        self.iprod = InnerProduct(timer, state, False)
        self.packrecon = PackRecon(timer)

    def common_coin(self, rid, field_len):
        randbits_per_share = field_len * Params.l
        num_shares = (Params.comp_sec + randbits_per_share - 1) // randbits_per_share

        self.state.new_prand(num_shares, field_len)
        rid = self.packrecon.run(rid, num_shares, field_len)

        return rid

    def delinearization(self, rid, field_len):
        inp_len = self.state.num_triples + sum(self.state.iprod)
        num_rand_pow = self.state.num_triples + len(self.state.iprod)
        self.timer.mult(rid, inp_len + num_rand_pow - 2, field_len)
        return self.common_coin(rid, field_len)

    def extended_compress(self, rid, inp_len, field_len):
        # Assumes 2 inputs
        self.timer.add(rid, 2 * inp_len, field_len)
        self.timer.mult(rid, 2 * inp_len, field_len)
        rid = self.iprod.run(rid, [inp_len], field_len)

        rid = self.common_coin(rid, field_len)
        self.timer.mult(rid, 9 + 2 * inp_len, field_len)
        self.timer.add(rid, 3 + 2 * inp_len, field_len)

        return rid

    def dimension_reduction(self, rid, inp_len, field_len):
        # Hardcoded value of K = inp_len / 2
        out_len = (inp_len + 1) // 2
        rid = self.iprod.run(rid, [out_len], field_len)
        self.timer.add(rid, 1, field_len)
        rid = self.extended_compress(rid, out_len, field_len)
        return (rid, out_len)

    def compress(self, rid, inp_len, field_len):
        self.timer.add(rid, 2 * inp_len, field_len)
        self.timer.mult(rid, 2 * inp_len, field_len)
        rid = self.mult.run(rid, inp_len - 1, field_len)

        rid = self.common_coin(rid, field_len)
        self.timer.add(rid, 9 + 2 * inp_len, field_len)
        self.timer.mult(rid, 9 + 2 * inp_len, field_len)

        return rid

    def randomization(self, rid, inp_len, field_len):
        self.state.new_prand(inp_len, field_len)
        rid = self.mult.run(rid, 2 * inp_len - 1, field_len)
        self.timer.add(rid, inp_len, field_len)
        rid = self.compress(rid, inp_len, field_len)
        rid = self.packrecon.run(rid, 3 * inp_len, field_len)
        return rid

    def run(self, rid, field_len):
        inp_len = self.state.num_triples + sum(self.state.iprod)
        rid = self.delinearization(rid, field_len)
        for _ in range(Params.MCheck_k):
            if inp_len / 2 < 1:
                break
            rid, inp_len = self.dimension_reduction(rid, inp_len, field_len)
        return self.randomization(rid, inp_len, field_len)


class Garble:
    def __init__(self, timer):
        self.timer = timer
        self.state = State()
        self.rid = 2
        self.mult = Multiplier(self.timer, self.state)
        self.iprod = InnerProduct(self.timer, self.state)

    def garble(self):
        and_batches = (Params.G_and + Params.l - 1) // Params.l
        xor_batches = (Params.G_xor + Params.l - 1) // Params.l
        num_batches = and_batches + xor_batches

        rid = self.rid

        # Select messages to encrypt.
        rid = self.mult.run(rid, and_batches, Params.F_len)
        rid = self.mult.run(rid, 4 * num_batches * Params.V, Params.F_len)

        # Compute MACs.
        mac_iprod_len = [Params.V + 1] * (4 * num_batches * (Params.V + 1))
        rid = self.iprod.run(rid, mac_iprod_len, Params.F_len)

        # Compute codeword for encryption.
        num_messages = 4 * num_batches
        self.timer.ecc(rid, num_messages)

        # Compute ciphertext.
        self.timer.add(rid, num_messages * Params.Q, Params.F_len)

        self.rid = rid

    def malicious_check(self):
        reps = int(math.ceil(Params.stat_sec / Params.F_len))
        rid = self.rid

        for _ in range(reps):
            rid = MaliciousCheckProd(self.timer, self.state).run(self.rid, Params.F_len)

        self.rid = rid


def cli_args():
    parser = argparse.ArgumentParser(
        description="Estimate computation time for each round of the garbling protocol.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("num_parties", type=int, help="Number of parties.")
    parser.add_argument(
        "threshold",
        type=int,
        help="Corruption threshold i.e., number of parties adversary can corrupt.",
    )
    parser.add_argument(
        "data_dir", help="Path to directory containing microbenchmarks."
    )
    parser.add_argument(
        "gates_and",
        type=int,
        help="Total number of AND gates in the circuit.",
    )
    parser.add_argument(
        "gates_xor",
        type=int,
        help="Total number of XOR gates in the circuit.",
    )
    parser.add_argument(
        "-d",
        "--field_degree",
        type=int,
        default=Params.F_len,
        help="Degree of polynomial modulus of extension field.",
    )
    parser.add_argument(
        "--stat_sec",
        default=Params.stat_sec,
        type=int,
        help="Statistical security parameter.",
    )
    parser.add_argument(
        "--comp_sec",
        default=Params.comp_sec,
        type=int,
        help="Computational security parameter.",
    )
    parser.add_argument(
        "--mcheck_k",
        default=Params.MCheck_k,
        type=int,
        help="Number of rounds for malicious check.",
    )
    parser.add_argument(
        "--hashlen",
        default=Params.HashLen,
        type=int,
        help="Length of output of hash function in bits.",
    )
    parser.add_argument(
        "--threads",
        default=1,
        type=int,
        help="Number of threads used for computation",
    )

    return parser.parse_args()


def fmt_time(num):
    units = ["ms", "s", "min"]
    to_next = [1000, 60, 60]

    for t, u in zip(to_next, units):
        if abs(num) < t:
            return f"{num:.3f} {u}"
        num /= t
    return f"{num:.3f} hours"


if __name__ == "__main__":
    args = cli_args()

    Params.n = args.num_parties
    Params.t = args.threshold
    Params.F_len = args.field_degree
    Params.stat_sec = args.stat_sec
    Params.comp_sec = args.comp_sec
    Params.MCheck_k = args.mcheck_k
    Params.G_and = args.gates_and
    Params.G_xor = args.gates_xor
    Params.HashLen = args.hashlen

    try:
        Params.initialize()
    except Exception as e:
        print(f"Error: {e}")
        raise SystemExit(0)

    timer = Timer(args.data_dir, args.threads)
    garble = Garble(timer)

    garble.garble()
    garble_time = sum(timer.round.values())
    print(f"Garble: {fmt_time(garble_time)}")

    garble.malicious_check()
    total_time = sum(timer.round.values())
    print(f"Malicious check: {fmt_time(total_time - garble_time)}")
    print(f"Total: {fmt_time(total_time)}")
