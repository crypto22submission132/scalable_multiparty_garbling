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


class Network:
    def __init__(self):
        self.comm = {}

    def __init_round(self, rid):
        if rid not in self.comm:
            self.comm[rid] = [[0 for _ in range(Params.n)] for _ in range(Params.n)]

    def communicate(self, rid, sender_pid, receiver_pid, num_bits):
        if num_bits == 0:
            return rid

        self.__init_round(rid)
        self.comm[rid][sender_pid][receiver_pid] += num_bits
        return rid + 1

    def all_to_one(self, rid, receiver_pid, num_bits):
        if num_bits == 0:
            return rid

        self.__init_round(rid)
        for i in range(Params.n):
            if i != receiver_pid:
                self.comm[rid][i][receiver_pid] += num_bits
        return rid + 1

    def one_to_all(self, rid, leader_pid, num_bits):
        if num_bits == 0:
            return rid

        self.__init_round(rid)
        for i in range(Params.n):
            if i != leader_pid:
                self.comm[rid][leader_pid][i] += num_bits
        return rid + 1

    def all_to_all(self, rid, num_bits):
        if num_bits == 0:
            return rid

        self.__init_round(rid)
        for i in range(Params.n):
            for j in range(Params.n):
                if i != j:
                    self.comm[rid][i][j] += num_bits
        return rid + 1

    def send_matrix(self, pid):
        matrix = []
        for _, round_comm in sorted(self.comm.items()):
            matrix.append(round_comm[pid])

        return matrix

    def recv_matrix(self, pid):
        matrix = []
        for _, round_comm in sorted(self.comm.items()):
            row = [0 for _ in range(Params.n)]
            for i in range(Params.n):
                row[i] = round_comm[i][pid]

            matrix.append(row)
        return matrix


class Multiplier:
    def __init__(self, network, state, robust=True):
        self.net = network
        self.state = state
        self.robust = robust

    def run(self, rid, num, field_len):
        rid = self.net.all_to_one(rid, 0, field_len * num)
        rid = self.net.one_to_all(rid, 0, field_len * num)

        if self.robust:
            self.state.add_triples(num)
        self.state.new_dprand(num, field_len)
        return rid


class InnerProduct:
    def __init__(self, network, state, robust=True):
        self.net = network
        self.state = state
        self.robust = robust

    def run(self, rid, inp_len_list, field_len):
        num_bits = len(inp_len_list) * field_len
        rid = self.net.all_to_one(rid, 0, num_bits)
        rid = self.net.one_to_all(rid, 0, num_bits)

        if self.robust:
            self.state.add_iprod(inp_len_list)
        self.state.new_dprand(len(inp_len_list), field_len)
        return rid


class ErrorGen:
    def __init__(self, network, state):
        self.net = network
        self.state = state

    def run(self, rid, num, field_len):
        rid = self.net.all_to_all(rid, num * field_len)
        self.state.add_triples(num)
        return rid


class BitRand:
    def __init__(self, network, state):
        self.net = network
        self.state = state

    def run(self, rid, num, field_len):
        num_shares = (num + Params.binH_k - 1) // Params.binH_k
        rid = self.net.all_to_all(rid, num_shares * field_len)
        self.state.add_triples(num)
        return rid


class PackRand:
    def __init__(self, network):
        self.net = network

    def run(self, rid, num, field_len):
        num_shares = (num + Params.n - Params.t - 1) // (Params.n - Params.t)
        rid = self.net.all_to_all(rid, num_shares * field_len)
        rid = self.net.all_to_all(rid, Params.t * num_shares * field_len)
        return rid


class DoublePRand:
    def __init__(self, network):
        self.net = network

    def run(self, rid, num, field_len):
        num_shares = (num + Params.n - Params.t - 1) // (Params.n - Params.t)
        rid = self.net.all_to_all(rid, 2 * num_shares * field_len)
        return rid


class PackRecon:
    def __init__(self, network):
        self.net = network

    def run(self, rid, num, field_len):
        return self.net.all_to_all(rid, num * field_len)


class MaliciousCheckProd:
    def __init__(self, network, state):
        self.net = network
        self.state = state
        self.mult = Multiplier(network, state, False)
        self.iprod = InnerProduct(network, state, False)
        self.packrecon = PackRecon(network)

    def common_coin(self, rid, field_len):
        randbits_per_share = field_len * Params.l
        num_shares = (Params.comp_sec + randbits_per_share - 1) // randbits_per_share

        self.state.new_prand(num_shares, field_len)
        rid = self.packrecon.run(rid, num_shares, field_len)

        return rid

    def delinearization(self, rid, field_len):
        return self.common_coin(rid, field_len)

    def extended_compress(self, rid, inp_len, field_len):
        # Assumes 2 inputs
        rid = self.iprod.run(rid, [inp_len], field_len)
        return self.common_coin(rid, field_len)

    def dimension_reduction(self, rid, inp_len, field_len):
        # Hardcoded value of K = inp_len / 2
        out_len = (inp_len + 1) // 2
        rid = self.iprod.run(rid, [out_len], field_len)
        rid = self.extended_compress(rid, out_len, field_len)
        return (rid, out_len)

    def compress(self, rid, inp_len, field_len):
        rid = self.mult.run(rid, inp_len - 1, field_len)
        return self.common_coin(rid, field_len)

    def randomization(self, rid, inp_len, field_len):
        self.state.new_prand(inp_len, field_len)
        rid = self.mult.run(rid, 2 * inp_len - 1, field_len)
        rid = self.compress(rid, inp_len, field_len)
        rid = self.packrecon.run(rid, 3, field_len)
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
    def __init__(self, network):
        self.net = network
        self.state = State()
        self.rid = 2

    def prepreproc(self):
        # Call this method at the end
        prand = PackRand(self.net)
        prand.run(0, self.state.num_prand.get(Params.F_len, 0), Params.F_len)
        prand.run(0, self.state.num_prand.get(Params.F_len, 0), Params.F_len)

        dprand = DoublePRand(self.net)
        dprand.run(0, self.state.num_dprand.get(Params.F_len, 0), Params.F_len)
        dprand.run(0, self.state.num_dprand.get(Params.F_len, 0), Params.F_len)

    def preproc(self):
        bitrand = BitRand(self.net, self.state)
        errorgen = ErrorGen(self.net, self.state)

        and_batches = (Params.G_and + Params.l - 1) // Params.l
        xor_batches = (Params.G_xor + Params.l - 1) // Params.l
        num_batches = and_batches + xor_batches
        num_wires = Params.G_and + Params.G_xor

        rid = self.rid

        num_bitrand = 0
        # Generate masks.
        num_bitrand += num_wires
        # Generate keys.
        num_bitrand += 2 * num_wires * Params.V
        # Generate MAC keys.
        num_bitrand += (Params.V + 1) * (Params.V + 2)
        brand_rid = bitrand.run(rid, num_bitrand, Params.F_len)

        egen_rid = errorgen.run(rid, 4 * Params.Q * num_batches, Params.F_len)

        self.rid = max(brand_rid, egen_rid)

    def garble(self):
        mult = Multiplier(self.net, self.state)
        inner_prod = InnerProduct(self.net, self.state)

        and_batches = (Params.G_and + Params.l - 1) // Params.l
        xor_batches = (Params.G_xor + Params.l - 1) // Params.l
        num_batches = and_batches + xor_batches

        rid = self.rid

        # Select messages to encrypt.
        rid = mult.run(rid, and_batches, Params.F_len)
        rid = mult.run(rid, 4 * num_batches * Params.V, Params.F_len)

        # Compute MACs.
        mac_iprod_len = [Params.V + 1] * (4 * num_batches * (Params.V + 1))
        rid = inner_prod.run(rid, mac_iprod_len, Params.F_len)

        self.rid = rid

    def malicious_check(self):
        reps = int(math.ceil(Params.stat_sec / Params.F_len))
        rid = self.rid

        for _ in range(reps):
            rid = MaliciousCheckProd(self.net, self.state).run(self.rid, Params.F_len)

        self.rid = rid
        self.rid = self.net.all_to_all(self.rid, Params.HashLen)


def cli_args():
    parser = argparse.ArgumentParser(
        description="Compute communication statistics for each round of the garbling protocol.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("num_parties", type=int, help="Number of parties.")
    parser.add_argument(
        "threshold",
        type=int,
        help="Corruption threshold i.e., number of parties adversary can corrupt.",
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
        "--preproc",
        default=False,
        action=argparse.BooleanOptionalAction,
        help="Compute cost for preprocessing too.",
    )
    parser.add_argument("-o", "--output", help="Directory to save the output.")

    return parser.parse_args()


def fmt_size(num, suffix="B"):
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
        if abs(num) < 1000.0:
            return f"{num:.3f} {unit}{suffix}"
        num /= 1000.0
    return f"{num:.1f} Y{suffix}"


if __name__ == "__main__":
    args = cli_args()

    Params.n = args.num_parties
    Params.t = args.threshold
    Params.stat_sec = args.stat_sec
    Params.comp_sec = args.comp_sec
    Params.F_len = args.field_degree
    Params.MCheck_k = args.mcheck_k
    Params.G_and = args.gates_and
    Params.G_xor = args.gates_xor
    Params.HashLen = args.hashlen

    try:
        Params.initialize()
    except Exception as e:
        print(f"Error: {e}")
        raise SystemExit(0)

    class SaveNetState:
        def __init__(self, net):
            self.rounds = len(net.comm.keys())
            self.total_comm = sum(map(lambda x: sum(map(sum, x)), net.comm.values()))

        @staticmethod
        def print_diff(start, end):
            rounds = end.rounds - start.rounds
            total_comm = (end.total_comm - start.total_comm) / 8

            print(f"Rounds: {rounds}")
            print(f"Total communication: {fmt_size(total_comm)}")
            print(f"Average communication: {fmt_size(total_comm / Params.n)}/party")

        def __str__(self):
            return f"Rounds: {self.rounds}, communication: {self.total_comm} bits"

    net = Network()
    garble = Garble(net)

    if args.preproc:
        preproc_st = SaveNetState(net)
        garble.preproc()
        preproc_ed = SaveNetState(net)

    garble_st = SaveNetState(net)
    garble.garble()
    garble_ed = SaveNetState(net)

    malchk_st = SaveNetState(net)
    garble.malicious_check()
    malchk_ed = SaveNetState(net)

    if args.preproc:
        st = SaveNetState(net)
        garble.prepreproc()
        ed = SaveNetState(net)

        rounds = preproc_ed.rounds - preproc_st.rounds + ed.rounds - st.rounds
        comm = (
            preproc_ed.total_comm
            - preproc_st.total_comm
            + st.total_comm
            - ed.total_comm
        ) / 8

        print("--- Preprocess --")
        print(f"Rounds: {rounds}")
        print(f"Total communication: {fmt_size(comm)}")
        print(f"Average communication: {fmt_size(comm / Params.n)}/party")
        print("")

    print("--- Garble ---")
    SaveNetState.print_diff(garble_st, garble_ed)

    print("\n--- Malicious Check ---")
    SaveNetState.print_diff(malchk_st, malchk_ed)

    if args.output is not None:
        os.makedirs(args.output, exist_ok=True)

        details = {
            "n": Params.n,
            "t": Params.t,
            "field_degree": Params.F_len,
            "stat_sec": Params.stat_sec,
            "comp_sec": Params.comp_sec,
            "MCheck_k": Params.MCheck_k,
            "G_and": Params.G_and,
            "G_xor": Params.G_xor,
            "HashLen": Params.HashLen,
        }

        with open(os.path.join(args.output, "details.json"), "w") as f:
            json.dump(details, f)

        for p in range(Params.n):
            save_data = {"send": net.send_matrix(p), "receive": net.recv_matrix(p)}

            with open(os.path.join(args.output, f"party_{p}.json"), "w") as f:
                json.dump(save_data, f)

        print("")
        print(f"Saved output in {args.output}.")
