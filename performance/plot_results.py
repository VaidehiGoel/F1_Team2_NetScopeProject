import csv
from pathlib import Path
import matplotlib.pyplot as plt

path = Path("results/benchmark_results.csv")
rows = list(csv.DictReader(path.read_text(encoding="utf-8").splitlines()))

x = [int(r["packets"]) for r in rows]
baseline = [float(r["baseline_seconds"]) for r in rows]
proposed = [float(r["proposed_seconds"]) for r in rows]
speedup = [float(r["speedup"]) for r in rows]

plt.figure(figsize=(9, 5))
plt.plot(x, baseline, marker="o", label="Baseline: repeated full scan")
plt.plot(x, proposed, marker="o", label="Proposed: incremental analysis")
plt.xlabel("Number of packets")
plt.ylabel("Time for repeated analysis workload (seconds)")
plt.title("NetScope Performance: Baseline vs Proposed")
plt.grid(True, alpha=0.25)
plt.legend()
plt.tight_layout()
plt.savefig("results/performance_graph.png", dpi=180)
plt.close()

plt.figure(figsize=(9, 5))
plt.plot(x, speedup, marker="o")
plt.xlabel("Number of packets")
plt.ylabel("Speedup (Baseline / Proposed)")
plt.title("NetScope Proposed Mechanism Speedup")
plt.grid(True, alpha=0.25)
plt.tight_layout()
plt.savefig("results/speedup_graph.png", dpi=180)
plt.close()

print("Created:")
print("  results/performance_graph.png")
print("  results/speedup_graph.png")
