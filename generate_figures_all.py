#!/usr/bin/env python3
"""
generate_figures_all.py
=======================
Loads results from ALL three datasets and generates:
  - Per-dataset comparison figures (Figs 1-7 x3 datasets)
  - Cross-dataset comparison figures (how M5 performs across datasets)
  - Combined LaTeX tables for the paper

RUN AFTER all three eval_*_all.py scripts have completed.

  python generate_figures_all.py

OUTPUTS (in results/figures/):
  per_dataset/  — 7 figures per dataset (21 total)
  cross/        — cross-dataset comparison figures
  tables/       — LaTeX and CSV tables
"""

import sys, json, csv
from pathlib import Path
import pandas as pd
import numpy as np

SCRIPT_DIR  = Path(__file__).parent
ROOT        = SCRIPT_DIR.parent if (SCRIPT_DIR.parent / "config.py").exists() \
              else SCRIPT_DIR
RESULTS_DIR = ROOT / "results"
FIG_DIR     = RESULTS_DIR / "figures"
(FIG_DIR / "per_dataset").mkdir(parents=True, exist_ok=True)
(FIG_DIR / "cross").mkdir(parents=True, exist_ok=True)
(FIG_DIR / "tables").mkdir(parents=True, exist_ok=True)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 10,
    "axes.titlesize": 11,
    "axes.labelsize": 10,
    "figure.dpi": 150,
    "axes.spines.top": False,
    "axes.spines.right": False,
})

# ── Dataset and method config ──────────────────────────────────
DATASETS = ["IoT23", "TON_IoT", "N-BaIoT"]
DATASET_LABELS = {"IoT23": "IoT-23", "TON_IoT": "TON_IoT", "N-BaIoT": "N-BaIoT"}

METHODS = [
    ("M0_Baseline",    "M0\nBaseline",      "#E74C3C"),
    ("M1_MerkleOnly",  "M1\nMerkle",        "#E67E22"),
    ("M2_AABF_Plus",   "M2\nAABF+",         "#F1C40F"),
    ("M3_BLS_Only",    "M3\nBLS",           "#2ECC71"),
    ("M4_Privacy_Mask","M4\nPrivacy",        "#3498DB"),
    ("M5_Hybrid",      "M5\nHybrid\n(Ours)","#9B59B6"),
]
M_KEYS   = [m[0] for m in METHODS]
M_LABELS = [m[1] for m in METHODS]
M_COLORS = [m[2] for m in METHODS]

# ── Load all CSV results ───────────────────────────────────────
all_data = {}   # dataset -> method_key -> DataFrame
summaries= {}   # dataset -> method_key -> summary dict

for ds in DATASETS:
    all_data[ds]  = {}
    summaries[ds] = {}
    ds_dir = RESULTS_DIR / ds

    # Load per-batch CSVs
    for mk, ml, mc in METHODS:
        csv_path = ds_dir / f"metrics_{mk}_{ds}.csv"
        if csv_path.exists():
            df = pd.read_csv(csv_path)
            all_data[ds][mk] = df

    # Load summary CSV
    summary_path = ds_dir / f"summary_ALL_{ds}.csv"
    if summary_path.exists():
        df_sum = pd.read_csv(summary_path)
        for _, row in df_sum.iterrows():
            method = row.get("method", "")
            for mk in M_KEYS:
                if mk in method:
                    summaries[ds][mk] = row.to_dict()
                    break

loaded = sum(len(all_data[ds]) for ds in DATASETS)
print(f"[figures] Loaded {loaded} method-dataset result sets")
if loaded == 0:
    print("ERROR: No results found. Run the eval_*_all.py scripts first.")
    sys.exit(1)


def per_reading(df, col):
    """Normalise metric by batch_size."""
    return (df[col] / df["batch_size"]).values


# ══════════════════════════════════════════════════════════════
# HELPER: per-dataset figures
# ══════════════════════════════════════════════════════════════
def make_dataset_figures(ds):
    ds_label = DATASET_LABELS.get(ds, ds)
    avail    = [(mk, ml, mc) for mk, ml, mc in METHODS if mk in all_data[ds]]
    if not avail:
        print(f"  [figures] No data for {ds} — skipping")
        return

    keys   = [m[0] for m in avail]
    labels = [m[1] for m in avail]
    colors = [m[2] for m in avail]
    out    = FIG_DIR / "per_dataset"

    # ── Fig A: Gas per reading ─────────────────────────────────
    fig, ax = plt.subplots(figsize=(9, 4))
    gas_vals = []
    for k in keys:
        df = all_data[ds][k]
        g  = per_reading(df, "gas_used").mean() if k != "M0_Baseline" \
             else df["gas_used"].mean()
        gas_vals.append(g)
    bars = ax.bar(labels, gas_vals, color=colors, edgecolor="white",
                  linewidth=1.2, width=0.55)
    for b, v in zip(bars, gas_vals):
        ax.text(b.get_x()+b.get_width()/2, b.get_height()+max(gas_vals)*0.01,
                f"{v:,.0f}", ha="center", va="bottom", fontsize=8, fontweight="bold")
    ax.set_ylabel("Gas units per reading")
    ax.set_title(f"Gas Cost per Reading — {ds_label} (Lower is Better)")
    ax.set_ylim(0, max(gas_vals)*1.22)
    plt.tight_layout()
    fig.savefig(out / f"fig_gas_{ds}.png", bbox_inches="tight")
    plt.close()

    # ── Fig B: Latency box plot ────────────────────────────────
    fig, ax = plt.subplots(figsize=(9, 4))
    lat_data = []
    for k in keys:
        df = all_data[ds][k]
        if k == "M0_Baseline":
            lat_data.append(df["latency_ms"].values)
        else:
            lat_data.append(per_reading(df, "latency_ms"))
    bp = ax.boxplot(lat_data, labels=labels, patch_artist=True,
                    medianprops=dict(color="black", linewidth=2),
                    whiskerprops=dict(linewidth=1.2))
    for patch, c in zip(bp["boxes"], colors):
        patch.set_facecolor(c); patch.set_alpha(0.7)
    ax.set_ylabel("Latency (ms per reading)")
    ax.set_title(f"Latency Distribution — {ds_label} (Lower is Better)")
    ax.set_yscale("log")
    plt.tight_layout()
    fig.savefig(out / f"fig_latency_{ds}.png", bbox_inches="tight")
    plt.close()

    # ── Fig C: Bandwidth per reading ──────────────────────────
    fig, ax = plt.subplots(figsize=(9, 4))
    bw_vals = []
    for k in keys:
        df = all_data[ds][k]
        bw = per_reading(df, "bandwidth_bytes").mean()
        bw_vals.append(bw)
    bars = ax.bar(labels, bw_vals, color=colors, edgecolor="white",
                  linewidth=1.2, width=0.55)
    for b, v in zip(bars, bw_vals):
        ax.text(b.get_x()+b.get_width()/2, b.get_height()+max(bw_vals)*0.01,
                f"{v:.1f}B", ha="center", va="bottom", fontsize=8)
    ax.set_ylabel("Bytes per reading (on-chain calldata)")
    ax.set_title(f"Bandwidth per Reading — {ds_label} (Lower is Better)")
    plt.tight_layout()
    fig.savefig(out / f"fig_bandwidth_{ds}.png", bbox_inches="tight")
    plt.close()

    # ── Fig D: Energy per reading ──────────────────────────────
    fig, ax = plt.subplots(figsize=(9, 4))
    dev_e  = [per_reading(all_data[ds][k], "energy_device_mj").mean() for k in keys]
    agg_e  = [per_reading(all_data[ds][k], "energy_aggr_mj").mean()   for k in keys]
    x      = np.arange(len(keys))
    ax.bar(x, dev_e, 0.5, label="IoT Device", color=colors, alpha=0.9)
    ax.bar(x, agg_e, 0.5, label="Aggregator", bottom=dev_e,
           color=colors, alpha=0.4, hatch="//")
    ax.set_xticks(x); ax.set_xticklabels(labels)
    ax.set_ylabel("Energy (mJ per reading)")
    ax.set_title(f"Energy Consumption — {ds_label} (Lower is Better)")
    ax.legend()
    plt.tight_layout()
    fig.savefig(out / f"fig_energy_{ds}.png", bbox_inches="tight")
    plt.close()

    # ── Fig E: Batch size distribution (M2 + M5 only) ─────────
    fig, axes = plt.subplots(1, 2, figsize=(10, 4), sharey=True)
    for ax, mk, title, c in [
        (axes[0], "M2_AABF_Plus", f"M2 AABF+ — {ds_label}", "#F1C40F"),
        (axes[1], "M5_Hybrid",    f"M5 Hybrid — {ds_label}", "#9B59B6"),
    ]:
        if mk in all_data[ds]:
            sizes = all_data[ds][mk]["batch_size"]
            ax.hist(sizes, bins=range(1, 55), color=c, edgecolor="white", alpha=0.85)
            ax.axvline(sizes.mean(), color="red", linestyle="--",
                       label=f"Mean={sizes.mean():.1f}")
            ax.set_xlabel("Batch Size"); ax.set_ylabel("Frequency")
            ax.set_title(title); ax.legend(fontsize=8)
        else:
            ax.text(0.5, 0.5, "No data", ha="center", transform=ax.transAxes)
    plt.tight_layout()
    fig.savefig(out / f"fig_batchsize_{ds}.png", bbox_inches="tight")
    plt.close()

    print(f"  [figures] {ds_label}: 5 figures saved to {out}")


# ── Generate per-dataset figures ───────────────────────────────
for ds in DATASETS:
    make_dataset_figures(ds)


# ══════════════════════════════════════════════════════════════
# CROSS-DATASET FIGURES
# ══════════════════════════════════════════════════════════════
print("\n[figures] Generating cross-dataset comparison figures...")

# Collect per-dataset averages for M5 only
m5_cross = {}
for ds in DATASETS:
    if "M5_Hybrid" in all_data[ds]:
        df = all_data[ds]["M5_Hybrid"]
        m5_cross[ds] = {
            "gas":       per_reading(df, "gas_used").mean(),
            "latency":   df["latency_ms"].mean(),
            "bandwidth": per_reading(df, "bandwidth_bytes").mean(),
            "energy":    (per_reading(df,"energy_device_mj") +
                          per_reading(df,"energy_aggr_mj")).mean(),
            "avg_batch": df["batch_size"].mean(),
        }

if m5_cross:
    ds_names = list(m5_cross.keys())
    fig, axes = plt.subplots(1, 4, figsize=(14, 4))
    metrics = [
        ("gas",       "Gas / Reading",    "#9B59B6"),
        ("latency",   "Avg Latency (ms)", "#3498DB"),
        ("bandwidth", "Bandwidth (B/rdg)","#2ECC71"),
        ("energy",    "Energy (mJ/rdg)",  "#E67E22"),
    ]
    for ax, (mk, title, c) in zip(axes, metrics):
        vals = [m5_cross[d][mk] for d in ds_names]
        bars = ax.bar([DATASET_LABELS.get(d,d) for d in ds_names],
                      vals, color=c, edgecolor="white", linewidth=1.2)
        for b, v in zip(bars, vals):
            ax.text(b.get_x()+b.get_width()/2, b.get_height()*1.02,
                    f"{v:,.1f}", ha="center", va="bottom", fontsize=8)
        ax.set_title(title, fontsize=10)
        ax.set_ylabel(title)
    fig.suptitle("M5 Hybrid Protocol — Cross-Dataset Performance Comparison",
                 fontsize=12, fontweight="bold", y=1.02)
    plt.tight_layout()
    fig.savefig(FIG_DIR/"cross"/"fig_m5_cross_dataset.png", bbox_inches="tight")
    plt.close()
    print("  [figures] Cross-dataset M5 comparison saved")

# Full cross-dataset gas comparison (all methods, all datasets)
fig, axes = plt.subplots(1, len([d for d in DATASETS if all_data[d]]),
                          figsize=(5*len(DATASETS), 4), sharey=False)
if len(DATASETS) == 1:
    axes = [axes]

for ax, ds in zip(axes, [d for d in DATASETS if all_data[d]]):
    avail_keys   = [k for k in M_KEYS   if k in all_data[ds]]
    avail_labels = [M_LABELS[M_KEYS.index(k)] for k in avail_keys]
    avail_colors = [M_COLORS[M_KEYS.index(k)] for k in avail_keys]
    gas_vals = []
    for k in avail_keys:
        df = all_data[ds][k]
        g  = per_reading(df, "gas_used").mean() if k != "M0_Baseline" \
             else df["gas_used"].mean()
        gas_vals.append(g)
    bars = ax.bar(avail_labels, gas_vals, color=avail_colors,
                  edgecolor="white", linewidth=1, width=0.6)
    for b, v in zip(bars, gas_vals):
        ax.text(b.get_x()+b.get_width()/2, b.get_height()*1.02,
                f"{v:,.0f}", ha="center", va="bottom", fontsize=7, rotation=30)
    ax.set_title(DATASET_LABELS.get(ds, ds))
    ax.set_ylabel("Gas / Reading")

fig.suptitle("Gas Cost per Reading — All Methods × All Datasets",
             fontsize=11, fontweight="bold")
plt.tight_layout()
fig.savefig(FIG_DIR/"cross"/"fig_gas_all_datasets.png", bbox_inches="tight")
plt.close()
print("  [figures] All-methods × all-datasets gas figure saved")


# ══════════════════════════════════════════════════════════════
# LATEX TABLES
# ══════════════════════════════════════════════════════════════
print("\n[figures] Generating LaTeX tables...")

for ds in DATASETS:
    if not summaries[ds]:
        continue
    ds_label = DATASET_LABELS.get(ds, ds)
    rows_tex = []
    rows_csv = []

    for mk, ml, _ in METHODS:
        s = summaries[ds].get(mk, {})
        if not s:
            continue
        row_tex = [
            ml.replace("\n", " "),
            f"{float(s.get('avg_gas_reading',0)):,.0f}",
            f"{float(s.get('avg_latency_ms',0)):.2f}",
            f"{float(s.get('p95_latency_ms',0)):.2f}",
            f"{float(s.get('avg_bw_reading',0)):.1f}",
            f"{float(s.get('avg_energy_reading',0)):.4f}",
            f"{float(s.get('avg_batch_size',0)):.1f}",
        ]
        rows_tex.append(row_tex)
        rows_csv.append(dict(
            method=ml.replace("\n"," "), dataset=ds_label,
            avg_gas_reading=s.get('avg_gas_reading',''),
            avg_latency_ms=s.get('avg_latency_ms',''),
            p95_latency_ms=s.get('p95_latency_ms',''),
            avg_bw_reading=s.get('avg_bw_reading',''),
            avg_energy_reading=s.get('avg_energy_reading',''),
            avg_batch_size=s.get('avg_batch_size',''),
        ))

    # CSV
    csv_path = FIG_DIR/"tables"/f"table_{ds}.csv"
    if rows_csv:
        with open(csv_path, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=list(rows_csv[0].keys()))
            w.writeheader(); w.writerows(rows_csv)

    # LaTeX
    hdrs = ["Method", "Gas/Rdg", "Lat(ms)", "P95 Lat", "BW(B)", "Energy(mJ)", "Batch"]
    cols = "l" + "r"*(len(hdrs)-1)
    tex_path = FIG_DIR/"tables"/f"table_{ds}.tex"
    lines = [
        r"\begin{table}[htbp]",
        r"\centering",
        f"\\caption{{Comparison of IoT-Blockchain Methods on {ds_label} Dataset}}",
        f"\\label{{tab:results_{ds.lower().replace('-','_')}}}",
        r"\resizebox{\textwidth}{!}{%",
        f"\\begin{{tabular}}{{{cols}}}",
        r"\hline",
        " & ".join(hdrs) + r" \\",
        r"\hline",
    ]
    for i, row in enumerate(rows_tex):
        bold = i == len(rows_tex)-1  # bold last row (M5)
        if bold:
            row = [f"\\textbf{{{v}}}" for v in row]
        lines.append(" & ".join(row) + r" \\")
    lines += [r"\hline", r"\end{tabular}}", r"\end{table}"]
    with open(tex_path, 'w') as f:
        f.write('\n'.join(lines))

    print(f"  [tables] {ds_label}: table_{ds}.csv  +  table_{ds}.tex")

# ── Master cross-dataset LaTeX table ──────────────────────────
master_csv = FIG_DIR/"tables"/"table_cross_dataset_M5.csv"
master_tex = FIG_DIR/"tables"/"table_cross_dataset_M5.tex"

cross_rows_tex = []
cross_rows_csv = []
for ds in DATASETS:
    s = summaries[ds].get("M5_Hybrid", {})
    if not s:
        continue
    cross_rows_tex.append([
        DATASET_LABELS.get(ds, ds),
        f"{float(s.get('avg_gas_reading',0)):,.0f}",
        f"{float(s.get('avg_latency_ms',0)):.2f}",
        f"{float(s.get('avg_bw_reading',0)):.1f}",
        f"{float(s.get('avg_energy_reading',0)):.4f}",
        f"{float(s.get('avg_batch_size',0)):.1f}",
        f"{int(s.get('urgent_flushes',0))}",
    ])
    cross_rows_csv.append(dict(
        dataset=DATASET_LABELS.get(ds,ds),
        avg_gas_reading=s.get('avg_gas_reading',''),
        avg_latency_ms=s.get('avg_latency_ms',''),
        avg_bw_reading=s.get('avg_bw_reading',''),
        avg_energy_reading=s.get('avg_energy_reading',''),
        avg_batch_size=s.get('avg_batch_size',''),
        urgent_flushes=s.get('urgent_flushes',''),
    ))

if cross_rows_csv:
    with open(master_csv, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(cross_rows_csv[0].keys()))
        w.writeheader(); w.writerows(cross_rows_csv)

    cross_hdrs = ["Dataset","Gas/Rdg","Lat(ms)","BW(B)","Energy(mJ)","AvgBatch","Urgent"]
    tex_lines = [
        r"\begin{table}[htbp]",
        r"\centering",
        r"\caption{Cross-Dataset Evaluation of Proposed Hybrid Protocol (M5)}",
        r"\label{tab:cross_dataset}",
        r"\begin{tabular}{lrrrrrr}",
        r"\hline",
        " & ".join(cross_hdrs) + r" \\",
        r"\hline",
    ] + [" & ".join(row) + r" \\" for row in cross_rows_tex] + \
        [r"\hline", r"\end{tabular}", r"\end{table}"]
    with open(master_tex, 'w') as f:
        f.write('\n'.join(tex_lines))
    print(f"  [tables] Cross-dataset M5 table: {master_csv.name}  +  {master_tex.name}")

print(f"\n[figures] ALL DONE")
print(f"  Per-dataset figures: {FIG_DIR/'per_dataset'}")
print(f"  Cross-dataset:       {FIG_DIR/'cross'}")
print(f"  LaTeX tables:        {FIG_DIR/'tables'}")
