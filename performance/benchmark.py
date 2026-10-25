import argparse
import csv
import os
import random
import statistics
import time
from collections import Counter


PROTOCOLS = ["TCP", "UDP", "ICMP", "ARP", "IPv4", "IPv6"]

IPS = [f"192.168.1.{i}" for i in range(2, 102)] + [
    "8.8.8.8",
    "1.1.1.1",
    "142.250.72.14",
    "172.217.160.46",
]


def make_packets(n, seed=42):
    rng = random.Random(seed)

    return [
        {
            "protocol": rng.choice(PROTOCOLS),
            "source": rng.choice(IPS),
            "destination": rng.choice(IPS),
            "length": rng.randint(54, 1500),
        }
        for _ in range(n)
    ]


def baseline(packet_list):
    """
    Baseline approach:
    Rescan the entire packet list for every statistics request.
    """

    protocols = Counter(p["protocol"] for p in packet_list)
    sources = Counter(p["source"] for p in packet_list)
    destinations = Counter(p["destination"] for p in packet_list)

    total_bytes = sum(p["length"] for p in packet_list)

    return (
        len(packet_list),
        total_bytes,
        protocols,
        sources,
        destinations,
    )


def proposed(packet_list):
    """
    Proposed approach:
    Build statistics using a single pass through the packet list.
    """

    protocols = Counter()
    sources = Counter()
    destinations = Counter()

    total_bytes = 0

    for p in packet_list:
        protocols[p["protocol"]] += 1
        sources[p["source"]] += 1
        destinations[p["destination"]] += 1
        total_bytes += p["length"]

    return (
        len(packet_list),
        total_bytes,
        protocols,
        sources,
        destinations,
    )


def repeated_analysis(method, packets, requests):
    """
    Runs an analysis method multiple times to simulate
    repeated dashboard statistics requests.
    """

    start = time.perf_counter()

    result = None

    for _ in range(requests):
        result = method(packets)

    elapsed = time.perf_counter() - start

    return elapsed, result


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--runs",
        type=int,
        default=10,
        help="Number of repeated benchmark runs"
    )

    parser.add_argument(
        "--requests",
        type=int,
        default=20,
        help="Number of repeated dashboard requests per run"
    )

    args = parser.parse_args()

    # Packet loads used for the experiment
    sizes = [
        100,
        500,
        1000,
        5000,
        10000,
        25000,
        50000
    ]

    # IMPORTANT:
    # This list must remain OUTSIDE the for loop.
    # Otherwise only the final packet count would be saved.
    out = []

    print("\n" + "=" * 75)
    print("NetScope Performance Experiment")
    print("=" * 75)

    print("\nBaseline  = repeated full packet-list rescans")
    print("Proposed  = incremental/cached statistics approach")

    print(
        f"\nRuns per configuration: {args.runs}"
        f"\nRequests per run:       {args.requests}\n"
    )

    print("-" * 75)

    for n in sizes:

        # Generate packets for this packet-count scenario
        packets = make_packets(n)

        base_times = []
        prop_times = []

        # ---------------------------------------------------------
        # REPEATED RUNS
        # ---------------------------------------------------------

        for run in range(args.runs):

            # Generate a slightly different packet set
            # for every run.
            packets_run = make_packets(
                n,
                seed=1000 + run
            )

            # =====================================================
            # BASELINE
            # =====================================================

            t0 = time.perf_counter()

            for _ in range(args.requests):
                baseline(packets_run)

            baseline_elapsed = time.perf_counter() - t0

            base_times.append(baseline_elapsed)

            # =====================================================
            # PROPOSED
            # =====================================================

            t0 = time.perf_counter()

            # Build statistics once.
            counters = {
                "p": Counter(),
                "s": Counter(),
                "d": Counter(),
                "b": 0
            }

            for p in packets_run:

                counters["p"][p["protocol"]] += 1
                counters["s"][p["source"]] += 1
                counters["d"][p["destination"]] += 1
                counters["b"] += p["length"]

            # Subsequent dashboard requests simply read
            # the already-maintained counters.
            for _ in range(args.requests):

                _ = (
                    len(packets_run),
                    counters["b"],
                    counters["p"].most_common(),
                    counters["s"].most_common(8),
                    counters["d"].most_common(8),
                )

            proposed_elapsed = time.perf_counter() - t0

            prop_times.append(proposed_elapsed)

        # =========================================================
        # CALCULATE STATISTICS
        # =========================================================

        # Mean execution time
        base_mean = statistics.mean(base_times)
        prop_mean = statistics.mean(prop_times)

        # Standard deviation
        if len(base_times) > 1:
            base_sd = statistics.stdev(base_times)
        else:
            base_sd = 0.0

        if len(prop_times) > 1:
            prop_sd = statistics.stdev(prop_times)
        else:
            prop_sd = 0.0

        # Speedup
        if prop_mean > 0:
            speedup = base_mean / prop_mean
        else:
            speedup = 0.0

        # Percentage improvement
        if base_mean > 0:
            improvement = (
                (base_mean - prop_mean)
                / base_mean
                * 100
            )
        else:
            improvement = 0.0

        # =========================================================
        # PRINT RESULTS
        # =========================================================

        print(
            f"{n:>6} packets | "
            f"Baseline: {base_mean:.6f}s "
            f"± {base_sd:.6f}s | "
            f"Proposed: {prop_mean:.6f}s "
            f"± {prop_sd:.6f}s | "
            f"Speedup: {speedup:.2f}x | "
            f"Improvement: {improvement:.2f}%"
        )

        # =========================================================
        # SAVE RESULT
        #
        # IMPORTANT:
        # This is INSIDE the for loop so that all seven packet
        # configurations are saved.
        # =========================================================

        out.append({
            "packets": n,
            "runs": args.runs,
            "requests_per_run": args.requests,

            "baseline_seconds": base_mean,
            "baseline_sd_seconds": base_sd,

            "proposed_seconds": prop_mean,
            "proposed_sd_seconds": prop_sd,

            "speedup": speedup,

            "improvement_percent": improvement,
        })

    # =============================================================
    # SAVE CSV
    # =============================================================

    results_dir = "results"

    # Create results directory if it doesn't already exist.
    os.makedirs(results_dir, exist_ok=True)

    results = os.path.join(
        results_dir,
        "benchmark_results.csv"
    )

    with open(
        results,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        fieldnames = [
            "packets",
            "runs",
            "requests_per_run",
            "baseline_seconds",
            "baseline_sd_seconds",
            "proposed_seconds",
            "proposed_sd_seconds",
            "speedup",
            "improvement_percent",
        ]

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )

        writer.writeheader()

        # Write ALL seven packet-count results.
        writer.writerows(out)

    # =============================================================
    # FINISHED
    # =============================================================

    print("-" * 75)

    print(
        f"\nSaved benchmark results to:\n"
        f"{results}"
    )

    print(
        f"\nTotal configurations recorded: {len(out)}"
    )

    print("\nExpected configurations:")

    for row in out:
        print(
            f"  {row['packets']:>6} packets"
        )

    print("\nBenchmark completed successfully.\n")


if __name__ == "__main__":
    main()