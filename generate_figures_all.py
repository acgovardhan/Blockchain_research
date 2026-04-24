#!/usr/bin/env python3
"""
generate_figures_all.py
=======================
Loads results from ALL three datasets and generates publication-quality figures
and tables for the IoT-Blockchain evaluation paper.

RUN AFTER all three datasets have been fully evaluated:
  python generate_figures_all.py

OUTPUTS (in results/figures/):
  per_dataset/   — 6 figures per dataset (18 total)
  cross/         — cross-dataset comparison figures
  tables/        — LaTeX and CSV tables

FIGURES GENERATED:
  Per dataset (×3):
    fig_gas_<ds>.png          — Gas cost per reading (bar)
    fig_latency_<ds>.png      — Latency box plot (log scale)
    fig_bandwidth_<ds>.png    — Bandwidth per reading (bar)
    fig_energy_<ds>.png       — Energy stacked bar (device + aggregator)
    fig_batchsize_<ds>.png    — Batch size distribution M2 vs M5
    fig_radar_<ds>.png        — Radar/spider chart all 5 metrics
  Cross-dataset:
    fig_gas_all_datasets.png          — Gas comparison all methods × all datasets
    fig_m5_cross_dataset.png          — M5 performance across datasets
    fig_latency_heatmap.png           — Latency heatmap methods × datasets
    fig_energy_heatmap.png            — Energy heatmap methods × datasets
    fig_improvement_over_m0.png       — % improvement of each method vs M0
    fig_tradeoff_gas_vs_latency.png   — Gas vs latency scatter (trade-off view)
  Tables:
    table_<ds>.csv / .tex             — Per-dataset summary table
    table_cross_dataset_M5.csv / .tex — Cross-dataset M5 table
    table_master_all.csv / .tex       — Master table all methods all datasets
"""

import sys
import csv
import warnings
from pathlib import Path

import pandas as pd
import numpy as np

warnings.filterwarnings("ignore")

SCRIPT_DIR  = Path(__file__).parent
ROOT        = SCRIPT_DIR.parent if (SCRIPT_DIR.parent / "config.py").exists() else SCRIPT_DIR
RESULTS_DIR = ROOT / "results"
FIG_DIR     = RESULTS_DIR / "figures"
(FIG_DIR / "per_dataset").mkdir(parents=True, exist_ok=True)
(FIG_DIR / "cross").mkdir(parents=True, exist_ok=True)
(FIG_DIR / "tables").mkdir(parents=True, exist_ok=True)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
from matplotlib.lines import Line2D
import seaborn as sns

# ── Publication-quality rcParams ──────────────────────────────
plt.rcParams.update({
    "font.family":        "DejaVu Sans",
    "font.size":          11,
    "axes.titlesize":     12,
    "axes.titleweight":   "bold",
    "axes.labelsize":     11,
    "axes.labelweight":   "bold",
    "xtick.labelsize":    10,
    "ytick.labelsize":    10,
    "legend.fontsize":    9,
    "legend.framealpha":  0.85,
    "figure.dpi":         200,
    "savefig.dpi":        300,
    "savefig.bbox":       "tight",
    "savefig.pad_inches": 0.05,
    "axes.spines.top":    False,
    "axes.spines.right":  False,
    "axes.grid":          True,
    "grid.alpha":         0.3,
    "grid.linestyle":     "--",
})

# ── Config ────────────────────────────────────────────────────
DATASETS = ["IoT23", "TON_IoT", "N-BaIoT"]
DATASET_LABELS = {
    "IoT23":   "IoT-23",
    "TON_IoT": "TON-IoT",
    "N-BaIoT": "N-BaIoT",
}

# Method definitions: (key, short_label, full_label, color)
METHODS = [
    ("M0_Baseline",     "M0",  "M0: Baseline\n(No Optimization)",  "#C0392B"),
    ("M1_MerkleOnly",   "M1",  "M1: Merkle\nAnchoring",            "#E67E22"),
    ("M2_AABF_Plus",    "M2",  "M2: AABF+\nAdaptive Batching",     "#F39C12"),
    ("M3_BLS_Only",     "M3",  "M3: BLS\nAggregate Sig",           "#27AE60"),
    ("M4_Privacy_Mask", "M4",  "M4: Privacy\nMasking",             "#2980B9"),
    ("M5_Hybrid",       "M5*", "M5: Hybrid\n(Proposed)",           "#8E44AD"),
]
M_KEYS    = [m[0] for m in METHODS]
M_SHORT   = [m[1] for m in METHODS]
M_FULL    = [m[2] for m in METHODS]
M_COLORS  = [m[3] for m in METHODS]

COLOR_MAP = dict(zip(M_KEYS, M_COLORS))
SHORT_MAP = dict(zip(M_KEYS, M_SHORT))
FULL_MAP  = dict(zip(M_KEYS, M_FULL))


# ══════════════════════════════════════════════════════════════
# DATA LOADING
# ══════════════════════════════════════════════════════════════
all_data  = {}   # ds -> method_key -> DataFrame (per-batch rows)
summaries = {}   # ds -> method_key -> dict of summary stats

for ds in DATASETS:
    all_data[ds]  = {}
    summaries[ds] = {}
    ds_dir = RESULTS_DIR / ds

    for mk in M_KEYS:
        csv_path = ds_dir / f"metrics_{mk}_{ds}.csv"
        if csv_path.exists():
            try:
                df = pd.read_csv(csv_path)
                if not df.empty:
                    all_data[ds][mk] = df
            except Exception as e:
                print(f"  [warn] Could not load {csv_path.name}: {e}")

    summary_path = ds_dir / f"summary_ALL_{ds}.csv"
    if summary_path.exists():
        try:
            df_sum = pd.read_csv(summary_path)
            for _, row in df_sum.iterrows():
                method_val = row.get("method", "")
                for mk in M_KEYS:
                    if mk in str(method_val):
                        summaries[ds][mk] = row.to_dict()
                        break
        except Exception as e:
            print(f"  [warn] Could not load summary for {ds}: {e}")

loaded = sum(len(all_data[ds]) for ds in DATASETS)
print(f"[figures] Loaded {loaded} method-dataset result sets")

if loaded == 0:
    print("ERROR: No results found. Run eval_fast.py for all three datasets first.")
    sys.exit(1)

# ── Helpers ───────────────────────────────────────────────────
def safe_float(val, default=0.0):
    try:
        return float(val)
    except Exception:
        return default

def per_reading(df, col):
    """Return per-reading values, normalised by batch_size."""
    return (df[col].astype(float) / df["batch_size"].astype(float)).values

def gas_per_reading(ds, mk):
    """
    M0 stores one reading per tx so gas_used IS per-reading already.
    All other methods store a batch so we normalise by batch_size.
    """
    if mk not in all_data[ds]:
        return np.array([])
    df = all_data[ds][mk]
    if mk == "M0_Baseline":
        return df["gas_used"].astype(float).values
    return per_reading(df, "gas_used")

def summary_val(ds, mk, key, default=0.0):
    return safe_float(summaries[ds].get(mk, {}).get(key, default))


# ══════════════════════════════════════════════════════════════
# PER-DATASET FIGURES
# ══════════════════════════════════════════════════════════════
def annotate_bars(ax, bars, vals, fmt="{:.0f}", rotation=0, color="black"):
    ymax = ax.get_ylim()[1]
    for b, v in zip(bars, vals):
        ax.text(
            b.get_x() + b.get_width() / 2,
            b.get_height() + ymax * 0.012,
            fmt.format(v),
            ha="center", va="bottom",
            fontsize=8, fontweight="bold",
            color=color, rotation=rotation,
        )


def make_dataset_figures(ds):
    ds_label = DATASET_LABELS.get(ds, ds)
    avail    = [(mk, SHORT_MAP[mk], COLOR_MAP[mk])
                for mk in M_KEYS if mk in all_data[ds]]
    if not avail:
        print(f"  [skip] No data for {ds}")
        return

    keys   = [a[0] for a in avail]
    labels = [a[1] for a in avail]
    colors = [a[2] for a in avail]
    out    = FIG_DIR / "per_dataset"

    # ── Fig 1: Gas per reading ─────────────────────────────────
    fig, ax = plt.subplots(figsize=(9, 4.5))
    gas_vals = [gas_per_reading(ds, k).mean() for k in keys]
    bars = ax.bar(labels, gas_vals, color=colors, edgecolor="white",
                  linewidth=1.5, width=0.6, zorder=3)
    ax.set_ylim(0, max(gas_vals) * 1.28)
    annotate_bars(ax, bars, gas_vals, fmt="{:,.0f}")
    ax.set_ylabel("Gas Units per Reading")
    ax.set_title(f"Gas Cost per IoT Reading — {ds_label}  (↓ Lower is Better)")
    ax.set_xlabel("Method")

    # Add note for M5
    if "M5_Hybrid" in keys:
        ax.annotate("* M5 = Proposed Hybrid Protocol",
                    xy=(0.98, 0.97), xycoords="axes fraction",
                    ha="right", va="top", fontsize=8, style="italic",
                    color="#8E44AD")
    plt.tight_layout()
    fig.savefig(out / f"fig_gas_{ds}.png")
    plt.close()

    # ── Fig 2: Latency box plot ────────────────────────────────
    fig, ax = plt.subplots(figsize=(9, 4.5))
    lat_data = []
    for k in keys:
        df = all_data[ds][k]
        vals = df["latency_ms"].astype(float).values if k == "M0_Baseline" \
               else per_reading(df, "latency_ms")
        lat_data.append(vals)

    bp = ax.boxplot(lat_data, labels=labels, patch_artist=True,
                    notch=False, showfliers=True,
                    flierprops=dict(marker=".", markersize=2, alpha=0.3),
                    medianprops=dict(color="white", linewidth=2.5),
                    whiskerprops=dict(linewidth=1.5),
                    capprops=dict(linewidth=1.5))
    for patch, c in zip(bp["boxes"], colors):
        patch.set_facecolor(c)
        patch.set_alpha(0.75)
    ax.set_yscale("log")
    ax.set_ylabel("Latency per Reading (ms, log scale)")
    ax.set_title(f"Latency Distribution — {ds_label}  (↓ Lower is Better)")
    ax.set_xlabel("Method")
    plt.tight_layout()
    fig.savefig(out / f"fig_latency_{ds}.png")
    plt.close()

    # ── Fig 3: Bandwidth per reading ──────────────────────────
    fig, ax = plt.subplots(figsize=(9, 4.5))
    bw_vals = [per_reading(all_data[ds][k], "bandwidth_bytes").mean() for k in keys]
    bars = ax.bar(labels, bw_vals, color=colors, edgecolor="white",
                  linewidth=1.5, width=0.6, zorder=3)
    ax.set_ylim(0, max(bw_vals) * 1.28)
    annotate_bars(ax, bars, bw_vals, fmt="{:.1f}B")
    ax.set_ylabel("Bytes per Reading (On-chain Calldata)")
    ax.set_title(f"Bandwidth Overhead per Reading — {ds_label}  (↓ Lower is Better)")
    ax.set_xlabel("Method")
    plt.tight_layout()
    fig.savefig(out / f"fig_bandwidth_{ds}.png")
    plt.close()

    # ── Fig 4: Energy stacked bar ──────────────────────────────
    fig, ax = plt.subplots(figsize=(9, 4.5))
    dev_e = [per_reading(all_data[ds][k], "energy_device_mj").mean() for k in keys]
    agg_e = [per_reading(all_data[ds][k], "energy_aggr_mj").mean()   for k in keys]
    x = np.arange(len(keys))

    b1 = ax.bar(x, dev_e, 0.55, label="IoT Device Energy",
                color=colors, alpha=0.95, edgecolor="white", linewidth=1.2, zorder=3)
    b2 = ax.bar(x, agg_e, 0.55, label="Aggregator Energy",
                bottom=dev_e, color=colors, alpha=0.45,
                hatch="///", edgecolor="white", linewidth=1.2, zorder=3)

    total_e = [d + a for d, a in zip(dev_e, agg_e)]
    ax.set_ylim(0, max(total_e) * 1.28)
    for xi, (d, t) in enumerate(zip(x, total_e)):
        ax.text(xi, t + max(total_e) * 0.012, f"{t:.3f}",
                ha="center", va="bottom", fontsize=8, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Energy Consumption (mJ per Reading)")
    ax.set_title(f"Energy Consumption — {ds_label}  (↓ Lower is Better)")
    ax.set_xlabel("Method")
    ax.legend(loc="upper left")
    plt.tight_layout()
    fig.savefig(out / f"fig_energy_{ds}.png")
    plt.close()

    # ── Fig 5: Batch size distribution M2 vs M5 ───────────────
    m2_avail = "M2_AABF_Plus" in all_data[ds]
    m5_avail = "M5_Hybrid"    in all_data[ds]
    if m2_avail or m5_avail:
        fig, axes = plt.subplots(1, 2, figsize=(11, 4.5), sharey=False)
        for ax, mk, title_label, c in [
            (axes[0], "M2_AABF_Plus", "M2: AABF+ Adaptive Batching", "#F39C12"),
            (axes[1], "M5_Hybrid",    "M5: Hybrid Protocol (Proposed)", "#8E44AD"),
        ]:
            if mk in all_data[ds]:
                sizes = all_data[ds][mk]["batch_size"].astype(int)
                mean_s, p95_s = sizes.mean(), np.percentile(sizes, 95)
                ax.hist(sizes, bins=range(1, 55), color=c, edgecolor="white",
                        alpha=0.85, zorder=3)
                ax.axvline(mean_s, color="red", linestyle="--", linewidth=2,
                           label=f"Mean = {mean_s:.1f}")
                ax.axvline(p95_s, color="navy", linestyle=":", linewidth=1.5,
                           label=f"P95 = {p95_s:.0f}")
                ax.set_xlabel("Batch Size (readings per tx)")
                ax.set_ylabel("Frequency")
                ax.set_title(f"{title_label}\n{ds_label}")
                ax.legend(fontsize=9)
            else:
                ax.text(0.5, 0.5, "No data available",
                        ha="center", va="center",
                        transform=ax.transAxes, fontsize=11, color="grey")
                ax.set_title(f"{title_label}\n{ds_label}")
        plt.suptitle(f"Adaptive Batch Size Distributions — {ds_label}", fontsize=12,
                     fontweight="bold", y=1.02)
        plt.tight_layout()
        fig.savefig(out / f"fig_batchsize_{ds}.png")
        plt.close()

    # ── Fig 6: Radar chart ─────────────────────────────────────
    metrics_for_radar = ["avg_gas_reading", "avg_latency_ms",
                         "avg_bw_reading", "avg_energy_reading", "avg_batch_size"]
    radar_labels = ["Gas/Rdg", "Latency", "Bandwidth", "Energy", "Avg Batch"]
    N = len(metrics_for_radar)

    # Collect raw values
    radar_raw = {}
    for k in keys:
        s = summaries[ds].get(k, {})
        if s:
            radar_raw[k] = [safe_float(s.get(m, 0)) for m in metrics_for_radar]

    if len(radar_raw) >= 3:
        # Normalise 0-1 per metric (higher = worse for all except batch size)
        arr = np.array([radar_raw[k] for k in radar_raw])
        col_max = arr.max(axis=0)
        col_max[col_max == 0] = 1
        arr_norm = arr / col_max
        # For batch size, higher is better so invert
        arr_norm[:, 4] = 1 - arr_norm[:, 4]

        angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
        angles += angles[:1]

        fig, ax = plt.subplots(figsize=(6.5, 6.5),
                               subplot_kw=dict(polar=True))
        for i, (k, row) in enumerate(zip(radar_raw.keys(), arr_norm)):
            vals = row.tolist() + row[:1].tolist()
            ax.plot(angles, vals, "o-", linewidth=2,
                    color=COLOR_MAP[k], label=SHORT_MAP[k], markersize=5)
            ax.fill(angles, vals, alpha=0.10, color=COLOR_MAP[k])

        ax.set_thetagrids(np.degrees(angles[:-1]), radar_labels, fontsize=10)
        ax.set_ylim(0, 1)
        ax.set_yticks([0.25, 0.5, 0.75, 1.0])
        ax.set_yticklabels(["25%", "50%", "75%", "100%"], fontsize=7)
        ax.set_title(f"Multi-Metric Radar — {ds_label}\n"
                     f"(normalised, lower area = better performance)",
                     fontsize=11, fontweight="bold", pad=18)
        ax.legend(loc="upper right", bbox_to_anchor=(1.32, 1.12), fontsize=9)
        plt.tight_layout()
        fig.savefig(out / f"fig_radar_{ds}.png")
        plt.close()

    print(f"  [per_dataset] {ds_label}: figures saved")


for ds in DATASETS:
    make_dataset_figures(ds)


# ══════════════════════════════════════════════════════════════
# CROSS-DATASET FIGURES
# ══════════════════════════════════════════════════════════════
print("\n[figures] Generating cross-dataset figures...")

out_cross = FIG_DIR / "cross"

# ── Cross 1: Gas all methods × all datasets (grouped bar) ─────
ds_with_data = [d for d in DATASETS if all_data[d]]
if ds_with_data:
    n_ds  = len(ds_with_data)
    n_met = len(M_KEYS)
    x     = np.arange(n_ds)
    width = 0.13
    offsets = np.linspace(-(n_met-1)/2*width, (n_met-1)/2*width, n_met)

    fig, ax = plt.subplots(figsize=(12, 5))
    for i, (mk, color) in enumerate(zip(M_KEYS, M_COLORS)):
        vals = []
        for ds in ds_with_data:
            g = gas_per_reading(ds, mk)
            vals.append(g.mean() if len(g) else 0)
        bars = ax.bar(x + offsets[i], vals, width, label=SHORT_MAP[mk],
                      color=color, edgecolor="white", linewidth=0.8, zorder=3)

    ax.set_xticks(x)
    ax.set_xticklabels([DATASET_LABELS.get(d, d) for d in ds_with_data], fontsize=11)
    ax.set_ylabel("Gas Units per Reading")
    ax.set_title("Gas Cost per Reading — All Methods × All Datasets  (↓ Lower is Better)",
                 fontsize=12)
    ax.legend(title="Method", loc="upper right", fontsize=9, ncol=2)
    plt.tight_layout()
    fig.savefig(out_cross / "fig_gas_all_datasets.png")
    plt.close()
    print("  [cross] Gas all-methods × all-datasets saved")

# ── Cross 2: M5 performance across datasets ───────────────────
m5_cross = {}
for ds in DATASETS:
    if "M5_Hybrid" in all_data[ds]:
        df = all_data[ds]["M5_Hybrid"]
        m5_cross[ds] = {
            "Gas/Rdg":      gas_per_reading(ds, "M5_Hybrid").mean(),
            "Latency (ms)": df["latency_ms"].astype(float).mean(),
            "BW (B/rdg)":   per_reading(df, "bandwidth_bytes").mean(),
            "Energy (mJ)":  (per_reading(df, "energy_device_mj") +
                             per_reading(df, "energy_aggr_mj")).mean(),
            "Avg Batch":    df["batch_size"].astype(float).mean(),
        }

if m5_cross:
    metric_keys = ["Gas/Rdg", "Latency (ms)", "BW (B/rdg)", "Energy (mJ)", "Avg Batch"]
    fig, axes = plt.subplots(1, 5, figsize=(16, 4.5))
    palette = ["#C0392B", "#E67E22", "#27AE60", "#2980B9", "#8E44AD"]
    for ax, mk, color in zip(axes, metric_keys, palette):
        ds_names = list(m5_cross.keys())
        vals = [m5_cross[d][mk] for d in ds_names]
        labels_ds = [DATASET_LABELS.get(d, d) for d in ds_names]
        bars = ax.bar(labels_ds, vals, color=color,
                      edgecolor="white", linewidth=1.2, width=0.55, zorder=3)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width()/2,
                    b.get_height() + max(vals) * 0.02,
                    f"{v:,.1f}", ha="center", va="bottom", fontsize=8, fontweight="bold")
        ax.set_title(mk, fontsize=10)
        ax.set_ylim(0, max(vals) * 1.3)
    fig.suptitle("M5 Hybrid Protocol (Proposed) — Cross-Dataset Performance",
                 fontsize=12, fontweight="bold", y=1.02)
    plt.tight_layout()
    fig.savefig(out_cross / "fig_m5_cross_dataset.png")
    plt.close()
    print("  [cross] M5 cross-dataset saved")

# ── Cross 3: Latency heatmap ───────────────────────────────────
lat_matrix = []
lat_row_labels = []
for mk in M_KEYS:
    row = []
    has = False
    for ds in DATASETS:
        if mk in all_data[ds]:
            df = all_data[ds][mk]
            v  = df["latency_ms"].astype(float).mean() if mk == "M0_Baseline" \
                 else per_reading(df, "latency_ms").mean()
            row.append(v)
            has = True
        else:
            row.append(np.nan)
    if has:
        lat_matrix.append(row)
        lat_row_labels.append(SHORT_MAP[mk])

if lat_matrix:
    arr = np.array(lat_matrix, dtype=float)
    fig, ax = plt.subplots(figsize=(7, 4.5))
    sns_ax = sns.heatmap(
        arr,
        annot=True, fmt=".1f", linewidths=0.5,
        xticklabels=[DATASET_LABELS.get(d, d) for d in DATASETS],
        yticklabels=lat_row_labels,
        cmap="YlOrRd",
        cbar_kws={"label": "Avg Latency (ms/reading)"},
        ax=ax,
    )
    ax.set_title("Average Latency (ms/reading) — Methods × Datasets\n(↓ Lower is Better)",
                 fontsize=11, fontweight="bold")
    plt.tight_layout()
    fig.savefig(out_cross / "fig_latency_heatmap.png")
    plt.close()
    print("  [cross] Latency heatmap saved")

# ── Cross 4: Energy heatmap ────────────────────────────────────
energy_matrix = []
energy_row_labels = []
for mk in M_KEYS:
    row = []
    has = False
    for ds in DATASETS:
        if mk in all_data[ds]:
            df = all_data[ds][mk]
            v  = (per_reading(df, "energy_device_mj") +
                  per_reading(df, "energy_aggr_mj")).mean()
            row.append(v)
            has = True
        else:
            row.append(np.nan)
    if has:
        energy_matrix.append(row)
        energy_row_labels.append(SHORT_MAP[mk])

if energy_matrix:
    arr = np.array(energy_matrix, dtype=float)
    fig, ax = plt.subplots(figsize=(7, 4.5))
    sns.heatmap(
        arr,
        annot=True, fmt=".4f", linewidths=0.5,
        xticklabels=[DATASET_LABELS.get(d, d) for d in DATASETS],
        yticklabels=energy_row_labels,
        cmap="Blues",
        cbar_kws={"label": "Total Energy (mJ/reading)"},
        ax=ax,
    )
    ax.set_title("Total Energy Consumption (mJ/reading) — Methods × Datasets\n(↓ Lower is Better)",
                 fontsize=11, fontweight="bold")
    plt.tight_layout()
    fig.savefig(out_cross / "fig_energy_heatmap.png")
    plt.close()
    print("  [cross] Energy heatmap saved")

# ── Cross 5: % improvement vs M0 baseline ─────────────────────
improve_data = {}
for ds in DATASETS:
    m0_gas = gas_per_reading(ds, "M0_Baseline").mean() if "M0_Baseline" in all_data[ds] else None
    if m0_gas is None or m0_gas == 0:
        continue
    improve_data[ds] = {}
    for mk in M_KEYS:
        if mk == "M0_Baseline" or mk not in all_data[ds]:
            continue
        g = gas_per_reading(ds, mk).mean()
        improve_data[ds][mk] = (1 - g / m0_gas) * 100  # % reduction

if improve_data:
    ds_list  = list(improve_data.keys())
    methods_for_improve = [mk for mk in M_KEYS if mk != "M0_Baseline"]
    n_ds  = len(ds_list)
    n_met = len(methods_for_improve)
    x     = np.arange(n_met)
    width = 0.22
    offsets = np.linspace(-(n_ds-1)/2*width, (n_ds-1)/2*width, n_ds)

    fig, ax = plt.subplots(figsize=(11, 5))
    ds_colors_bar = ["#2980B9", "#27AE60", "#C0392B"]
    for i, (ds, dc) in enumerate(zip(ds_list, ds_colors_bar)):
        vals = [improve_data[ds].get(mk, 0) for mk in methods_for_improve]
        bars = ax.bar(x + offsets[i], vals, width,
                      label=DATASET_LABELS.get(ds, ds),
                      color=dc, edgecolor="white", linewidth=0.8,
                      alpha=0.85, zorder=3)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width()/2,
                    b.get_height() + 0.5,
                    f"{v:.1f}%", ha="center", va="bottom",
                    fontsize=7.5, fontweight="bold", color=dc)

    ax.axhline(0, color="black", linewidth=1.0)
    ax.set_xticks(x)
    ax.set_xticklabels([SHORT_MAP[mk] for mk in methods_for_improve], fontsize=11)
    ax.set_ylabel("Gas Cost Reduction vs M0 Baseline (%)")
    ax.set_title("Gas Efficiency Improvement vs M0 Baseline — All Datasets  (↑ Higher is Better)",
                 fontsize=11)
    ax.legend(title="Dataset", fontsize=9)
    plt.tight_layout()
    fig.savefig(out_cross / "fig_improvement_over_m0.png")
    plt.close()
    print("  [cross] Improvement over M0 saved")

# ── Cross 6: Gas vs Latency trade-off scatter ──────────────────
fig, axes = plt.subplots(1, len(ds_with_data), figsize=(5.5 * len(ds_with_data), 5))
if len(ds_with_data) == 1:
    axes = [axes]

for ax, ds in zip(axes, ds_with_data):
    ds_label = DATASET_LABELS.get(ds, ds)
    for mk in M_KEYS:
        if mk not in all_data[ds]:
            continue
        df = all_data[ds][mk]
        g  = gas_per_reading(ds, mk).mean()
        l  = (df["latency_ms"].astype(float).mean() if mk == "M0_Baseline"
              else per_reading(df, "latency_ms").mean())
        c  = COLOR_MAP[mk]
        lbl = SHORT_MAP[mk]
        ax.scatter(g, l, s=200, color=c, zorder=5, edgecolors="white",
                   linewidth=1.5, label=lbl)
        ax.annotate(lbl, (g, l),
                    textcoords="offset points", xytext=(6, 4),
                    fontsize=9, fontweight="bold", color=c)
    ax.set_xlabel("Gas per Reading")
    ax.set_ylabel("Avg Latency (ms)")
    ax.set_title(f"Gas vs Latency Trade-off\n{ds_label}")
    ax.legend(fontsize=8, loc="upper left")

plt.suptitle("Cost–Latency Trade-off: Methods vs Datasets  (↙ Bottom-left is ideal)",
             fontsize=11, fontweight="bold", y=1.02)
plt.tight_layout()
fig.savefig(out_cross / "fig_tradeoff_gas_vs_latency.png")
plt.close()
print("  [cross] Gas vs latency trade-off scatter saved")


# ══════════════════════════════════════════════════════════════
# LATEX + CSV TABLES
# ══════════════════════════════════════════════════════════════
print("\n[figures] Generating tables...")

out_tables = FIG_DIR / "tables"

# ── Per-dataset tables ─────────────────────────────────────────
for ds in DATASETS:
    if not summaries[ds]:
        continue
    ds_label = DATASET_LABELS.get(ds, ds)
    rows_tex = []
    rows_csv = []

    for mk in M_KEYS:
        s = summaries[ds].get(mk, {})
        if not s:
            continue
        method_label = SHORT_MAP[mk]
        is_proposed  = mk == "M5_Hybrid"

        g   = safe_float(s.get("avg_gas_reading", 0))
        l   = safe_float(s.get("avg_latency_ms", 0))
        p95 = safe_float(s.get("p95_latency_ms", 0))
        bw  = safe_float(s.get("avg_bw_reading", 0))
        e   = safe_float(s.get("avg_energy_reading", 0))
        bs  = safe_float(s.get("avg_batch_size", 0))
        urg = int(safe_float(s.get("urgent_flushes", 0)))

        row_vals = [
            method_label,
            f"{g:,.0f}",
            f"{l:.2f}",
            f"{p95:.2f}",
            f"{bw:.1f}",
            f"{e:.4f}",
            f"{bs:.1f}",
            str(urg),
        ]

        if is_proposed:
            row_vals = [f"\\textbf{{{v}}}" for v in row_vals]
            row_vals[0] = f"\\textbf{{{SHORT_MAP[mk]}}} (Proposed)"

        rows_tex.append(row_vals)
        rows_csv.append({
            "method": SHORT_MAP[mk],
            "dataset": ds_label,
            "avg_gas_reading": f"{g:,.0f}",
            "avg_latency_ms": f"{l:.2f}",
            "p95_latency_ms": f"{p95:.2f}",
            "avg_bw_reading": f"{bw:.1f}",
            "avg_energy_reading": f"{e:.4f}",
            "avg_batch_size": f"{bs:.1f}",
            "urgent_flushes": str(urg),
        })

    # CSV
    if rows_csv:
        csv_path = out_tables / f"table_{ds}.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows_csv[0].keys()))
            w.writeheader()
            w.writerows(rows_csv)

    # LaTeX
    hdrs = ["Method", "Gas/Rdg", "Lat(ms)", "P95(ms)", "BW(B)", "Energy(mJ)", "Batch", "Urgent"]
    cols = "l" + "r" * (len(hdrs) - 1)
    tex_path = out_tables / f"table_{ds}.tex"
    lines = [
        r"\begin{table}[htbp]",
        r"\centering",
        (f"\\caption{{Performance Comparison of IoT Blockchain Methods on "
         f"{ds_label} Dataset}}"),
        f"\\label{{tab:results_{ds.lower().replace('-','_').replace(' ','_')}}}",
        r"\resizebox{\textwidth}{!}{%",
        f"\\begin{{tabular}}{{{cols}}}",
        r"\hline",
        " & ".join(hdrs) + r" \\",
        r"\hline",
    ]
    for row in rows_tex:
        lines.append(" & ".join(row) + r" \\")
    lines += [
        r"\hline",
        r"\multicolumn{" + str(len(hdrs)) + r"}{l}{\footnotesize "
        r"Gas/Rdg: gas units per reading. Lat: average latency. "
        r"P95: 95th percentile latency. BW: on-chain calldata bytes. "
        r"Energy: total mJ per reading. Batch: avg readings per tx. "
        r"Urgent: force-flush events. * M5 is the proposed protocol.} \\",
        r"\hline",
        r"\end{tabular}}",
        r"\end{table}",
    ]
    with open(tex_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"  [tables] {ds_label}: table_{ds}.csv + table_{ds}.tex")

# ── Master table (all methods × all datasets) ──────────────────
master_rows_csv = []
master_rows_tex = []

for ds in DATASETS:
    for mk in M_KEYS:
        s = summaries[ds].get(mk, {})
        if not s:
            continue
        g   = safe_float(s.get("avg_gas_reading", 0))
        l   = safe_float(s.get("avg_latency_ms", 0))
        bw  = safe_float(s.get("avg_bw_reading", 0))
        e   = safe_float(s.get("avg_energy_reading", 0))
        bs  = safe_float(s.get("avg_batch_size", 0))
        is_proposed = mk == "M5_Hybrid"
        master_rows_csv.append({
            "dataset":           DATASET_LABELS.get(ds, ds),
            "method":            SHORT_MAP[mk],
            "avg_gas_reading":   f"{g:,.0f}",
            "avg_latency_ms":    f"{l:.2f}",
            "avg_bw_reading":    f"{bw:.1f}",
            "avg_energy_reading":f"{e:.4f}",
            "avg_batch_size":    f"{bs:.1f}",
        })
        row_vals = [
            DATASET_LABELS.get(ds, ds),
            SHORT_MAP[mk] + (" *" if is_proposed else ""),
            f"{g:,.0f}",
            f"{l:.2f}",
            f"{bw:.1f}",
            f"{e:.4f}",
            f"{bs:.1f}",
        ]
        if is_proposed:
            row_vals = [f"\\textbf{{{v}}}" for v in row_vals]
        master_rows_tex.append(row_vals)

if master_rows_csv:
    with open(out_tables / "table_master_all.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(master_rows_csv[0].keys()))
        w.writeheader()
        w.writerows(master_rows_csv)

    master_hdrs = ["Dataset", "Method", "Gas/Rdg", "Lat(ms)", "BW(B)", "Energy(mJ)", "Batch"]
    cols = "ll" + "r" * (len(master_hdrs) - 2)
    lines = [
        r"\begin{table*}[htbp]",
        r"\centering",
        r"\caption{Comprehensive Evaluation Results: All Methods Across All Datasets}",
        r"\label{tab:master_results}",
        r"\resizebox{\textwidth}{!}{%",
        f"\\begin{{tabular}}{{{cols}}}",
        r"\hline",
        " & ".join(master_hdrs) + r" \\",
        r"\hline",
    ]
    prev_ds = None
    for row in master_rows_tex:
        ds_val = row[0].replace("\\textbf{", "").replace("}", "")
        if ds_val != prev_ds and prev_ds is not None:
            lines.append(r"\hline")
        prev_ds = ds_val
        lines.append(" & ".join(row) + r" \\")
    lines += [
        r"\hline",
        r"\multicolumn{" + str(len(master_hdrs)) + r"}{l}{\footnotesize "
        r"* M5 is the proposed Hybrid Protocol. "
        r"Gas/Rdg normalised per reading. Energy = device + aggregator.} \\",
        r"\hline",
        r"\end{tabular}}",
        r"\end{table*}",
    ]
    with open(out_tables / "table_master_all.tex", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("  [tables] Master table: table_master_all.csv + table_master_all.tex")

# ── Cross-dataset M5 table ─────────────────────────────────────
cross_rows_csv = []
cross_rows_tex = []
for ds in DATASETS:
    s = summaries[ds].get("M5_Hybrid", {})
    if not s:
        continue
    g   = safe_float(s.get("avg_gas_reading", 0))
    l   = safe_float(s.get("avg_latency_ms", 0))
    p95 = safe_float(s.get("p95_latency_ms", 0))
    bw  = safe_float(s.get("avg_bw_reading", 0))
    e   = safe_float(s.get("avg_energy_reading", 0))
    bs  = safe_float(s.get("avg_batch_size", 0))
    urg = int(safe_float(s.get("urgent_flushes", 0)))
    n   = int(safe_float(s.get("total_readings", 0)))

    cross_rows_csv.append({
        "dataset": DATASET_LABELS.get(ds, ds),
        "total_readings": str(n),
        "avg_gas_reading": f"{g:,.0f}",
        "avg_latency_ms": f"{l:.2f}",
        "p95_latency_ms": f"{p95:.2f}",
        "avg_bw_reading": f"{bw:.1f}",
        "avg_energy_reading": f"{e:.4f}",
        "avg_batch_size": f"{bs:.1f}",
        "urgent_flushes": str(urg),
    })
    cross_rows_tex.append([
        DATASET_LABELS.get(ds, ds),
        f"{n:,}",
        f"{g:,.0f}",
        f"{l:.2f}",
        f"{p95:.2f}",
        f"{bw:.1f}",
        f"{e:.4f}",
        f"{bs:.1f}",
        str(urg),
    ])

if cross_rows_csv:
    with open(out_tables / "table_cross_dataset_M5.csv", "w", newline="",
              encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(cross_rows_csv[0].keys()))
        w.writeheader()
        w.writerows(cross_rows_csv)

    ch = ["Dataset", "N", "Gas/Rdg", "Lat(ms)", "P95(ms)", "BW(B)", "Energy(mJ)", "Batch", "Urgent"]
    lines = [
        r"\begin{table}[htbp]",
        r"\centering",
        r"\caption{Cross-Dataset Evaluation of the Proposed Hybrid Protocol (M5)}",
        r"\label{tab:cross_dataset_m5}",
        r"\resizebox{\textwidth}{!}{%",
        f"\\begin{{tabular}}{{l{'r'*(len(ch)-1)}}}",
        r"\hline",
        " & ".join(ch) + r" \\",
        r"\hline",
    ] + [" & ".join(row) + r" \\" for row in cross_rows_tex] + [
        r"\hline",
        r"\end{tabular}}",
        r"\end{table}",
    ]
    with open(out_tables / "table_cross_dataset_M5.tex", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("  [tables] Cross-dataset M5 table saved")


# ══════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════
per_ds_figs  = list((FIG_DIR / "per_dataset").glob("*.png"))
cross_figs   = list((FIG_DIR / "cross").glob("*.png"))
table_files  = list(out_tables.glob("*"))

print(f"\n{'='*60}")
print(f"  ALL FIGURES AND TABLES GENERATED")
print(f"{'='*60}")
print(f"  Per-dataset figures : {len(per_ds_figs):>3}  →  {FIG_DIR/'per_dataset'}")
print(f"  Cross-dataset figs  : {len(cross_figs):>3}  →  {FIG_DIR/'cross'}")
print(f"  Table files (csv+tex): {len(table_files):>3}  →  {out_tables}")
print(f"\n  Per-dataset figures (×{len(DATASETS)} datasets):")
print(f"    fig_gas_*          — Gas cost bar chart")
print(f"    fig_latency_*      — Latency box plot (log scale)")
print(f"    fig_bandwidth_*    — Bandwidth bar chart")
print(f"    fig_energy_*       — Energy stacked bar")
print(f"    fig_batchsize_*    — M2 vs M5 batch distribution")
print(f"    fig_radar_*        — Multi-metric radar chart")
print(f"\n  Cross-dataset figures:")
print(f"    fig_gas_all_datasets       — All methods × all datasets")
print(f"    fig_m5_cross_dataset       — M5 across 3 datasets")
print(f"    fig_latency_heatmap        — Latency heatmap")
print(f"    fig_energy_heatmap         — Energy heatmap")
print(f"    fig_improvement_over_m0    — % gas reduction vs baseline")
print(f"    fig_tradeoff_gas_vs_latency — Cost-latency scatter")
print(f"\n  LaTeX tables (drop directly into paper):")
print(f"    table_IoT23.tex / table_TON_IoT.tex / table_N-BaIoT.tex")
print(f"    table_master_all.tex       — All methods × all datasets")
print(f"    table_cross_dataset_M5.tex — M5 cross-dataset table")
print(f"{'='*60}")
