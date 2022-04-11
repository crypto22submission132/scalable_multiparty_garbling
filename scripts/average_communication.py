import os
import json
import argparse

def fmt_time(num):
    units = ["ms", "s", "min"]
    to_next = [1000, 60, 60]

    for t, u in zip(to_next, units):
        if abs(num) < t:
            return f"{num:.3f} {u}"
        num /= t
    return f"{num:.3f} hours"


def print_times(n, data_dir):
    garble_time = 0
    mcheck_time = 0
    total_time = 0

    for i in range(n):
        with open(os.path.join(data_dir, f"party_{i}.json"), "r") as f:
            data = json.load(f)

        cgt = 0
        cmt = 0
        ctt = 0
        for rep in data:
            cgt += sum(rep[:6])
            cmt += sum(rep[6:])
            ctt += sum(rep)
        cgt /= len(data)
        cmt /= len(data)
        ctt /= len(data)

        garble_time += cgt
        mcheck_time += cmt
        total_time += ctt

    garble_time /= n
    mcheck_time /= n
    total_time /= n

    print(f"Garble: {fmt_time(garble_time)}")
    print(f"Malicious Check: {fmt_time(mcheck_time)}")
    print(f"Total: {fmt_time(total_time)}")


def cli_args():
    parser = argparse.ArgumentParser(
        description="Compute average communication time across parties.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("num_parties", type=int, help="Number of parties.")
    parser.add_argument(
        "data_dir", help="Path to directory containing microbenchmarks."
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = cli_args()
    print_times(args.num_parties, args.data_dir)
