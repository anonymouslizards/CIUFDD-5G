import argparse
import gc
import glob
import os
import re
import subprocess
import sys
import time

import matplotlib.pyplot as plt
from matplotlib.ticker import LogLocator, MaxNLocator, MultipleLocator
import numpy as np
import pandas as pd

ATTACKER_COUNTS = [2, 3, 4, 5, 6, 7, 8, 9, 10]
REPORT_PATTERN = "txt/udp-n{n}-dmgnbat-run*"
CONCENTRATED_REPORT_PATTERN = "txt/udp-n{n}-csgnbat-run*"
DATASET_PATTERN = "datasets/udp-n{n}-labeled-dmgnbat-run*.csv"
CONCENTRATED_DATASET_PATTERN = "datasets/udp-n{n}-labeled-csgnbat-run*.csv"
IMG_DIR = "img"
SEED = 42
DEFAULT_MAX_MEM_PCT = 50
POLL_INTERVAL_S = 2
PLOT_CHUNK_SIZE = 50000


def get_total_memory_kb():
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemTotal:"):
                return int(line.split()[1])
    return None


def get_rss_kb(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except FileNotFoundError:
        return None
    return None


def get_descendant_pids(pid):
    pids = [pid]
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/status") as f:
                for line in f:
                    if line.startswith("PPid:") and int(line.split()[1]) == pid:
                        pids.extend(get_descendant_pids(int(entry)))
                        break
        except (FileNotFoundError, ProcessLookupError):
            continue
    return pids


def get_tree_rss_kb(pid):
    return sum(rss for p in get_descendant_pids(pid) if (rss := get_rss_kb(p)))


def run_simulation(max_mem_pct, mode):
    cmd = f'./ns3 run "ciufdd-5g --{mode}"'

    total_kb = get_total_memory_kb()
    max_rss_kb = (total_kb * max_mem_pct // 100) if total_kb else None

    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    while proc.poll() is None:
        if max_rss_kb and get_tree_rss_kb(proc.pid) > max_rss_kb:
            proc.kill()
            proc.wait()
            return False
        time.sleep(POLL_INTERVAL_S)

    return proc.returncode == 0


def parse_report(path):
    text = open(path).read()
    blocks = re.split(r"\nFlow \d+ ", "\n" + text)[1:]

    records = []
    for b in blocks:
        label_match = re.search(r"label=(\w+)", b)
        if not label_match:
            continue

        def grab(pattern, cast=float, default=0):
            m = re.search(pattern, b)
            return cast(m.group(1)) if m else default

        records.append({
            "label": label_match.group(1),
            "tx_packets": grab(r"Tx Packets:\s+(\d+)", int),
            "throughput_mbps": grab(r"Throughput:\s+([\d.]+) Mbps"),
            "mean_delay_ms": grab(r"Mean delay:\s+([\d.]+) ms"),
            "mean_jitter_ms": grab(r"Mean jitter:\s+([\d.]+) ms"),
            "rx_packets": grab(r"Rx Packets:\s+(\d+)", int),
        })

    return pd.DataFrame(records)


def summarize(df):
    out = {}
    for label, g in df.groupby("label"):
        tx_total = g.tx_packets.sum()
        rx_total = g.rx_packets.sum()
        loss_pct = 100 * (1 - rx_total / tx_total) if tx_total else 0.0

        g_delivered = g[g.rx_packets > 0]
        delay_mean = g_delivered.mean_delay_ms.mean() if len(g_delivered) else float("nan")
        jitter_mean = g_delivered.mean_jitter_ms.mean() if len(g_delivered) else float("nan")

        out[label] = {
            "throughput_mbps": round(g.throughput_mbps.mean(), 4),
            "delay_ms": round(delay_mean, 2) if delay_mean == delay_mean else None,
            "jitter_ms": round(jitter_mean, 3) if jitter_mean == jitter_mean else None,
            "packet_loss_pct": round(loss_pct, 2),
            "flows_with_zero_delivery": int((g.rx_packets == 0).sum()),
        }
    return out


def aggregate_metric(values):
    """Mean and sample std-dev across seeds for one metric. None entries
    (e.g. delay/jitter when a flow never delivered) are dropped first;
    returns (None, None) if nothing usable remains. Std is 0.0, not NaN,
    when only one seed contributed a value."""
    clean = [v for v in values if v is not None]
    if not clean:
        return None, None
    s = pd.Series(clean, dtype="float64")
    mean = round(s.mean(), 4)
    std = round(s.std(), 4) if len(clean) > 1 else 0.0
    return mean, std


def build_row(n_attackers, report_pattern):
    paths = sorted(glob.glob(report_pattern.format(n=n_attackers)))
    if not paths:
        return None

    per_seed = []
    for path in paths:
        df = parse_report(path)
        per_seed.append(summarize(df))

    def collect(label, key):
        return [s.get(label, {}).get(key) for s in per_seed]

    metrics = {
        "normal_throughput_mbps": collect("normal", "throughput_mbps"),
        "normal_delay_ms": collect("normal", "delay_ms"),
        "normal_jitter_ms": collect("normal", "jitter_ms"),
        "normal_packet_loss_pct": collect("normal", "packet_loss_pct"),
        "attack_throughput_mbps": collect("attack", "throughput_mbps"),
        "attack_delay_ms": collect("attack", "delay_ms"),
        "attack_jitter_ms": collect("attack", "jitter_ms"),
        "attack_packet_loss_pct": collect("attack", "packet_loss_pct"),
        "attack_flows_zero_delivery": collect("attack", "flows_with_zero_delivery"),
    }

    row = {"attackers": n_attackers, "seeds": len(paths)}
    for name, values in metrics.items():
        mean, std = aggregate_metric(values)
        row[f"{name}_mean"] = mean
        row[f"{name}_std"] = std
    return row


def run_table(args):
    mode = "csgnbat" if args.csgnbat else "dmgnbat"
    report_pattern = CONCENTRATED_REPORT_PATTERN if args.csgnbat else REPORT_PATTERN

    if not args.skip_run:
        ok = run_simulation(args.max_mem_pct, mode)
        if not ok:
            sys.exit("Simulation run was killed (RAM guard) or failed; no results were produced.")

    rows = []
    for n in ATTACKER_COUNTS:
        row = build_row(n, report_pattern)
        if row is None:
            continue
        rows.append(row)

    if not rows:
        sys.exit("No results to report: no report files were found.")

    result = pd.DataFrame(rows).sort_values("attackers").reset_index(drop=True)
    print(result.to_string(index=False))


def tag_from_csv(csv_path):
    basename = os.path.basename(csv_path)
    match = re.match(r"^udp-(n\d+)-labeled-(dmgnbat|csgnbat)(?:-run\d+)?\.csv$", basename)
    return f"{match.group(1)}-{match.group(2)}" if match else "output"


def run_list(args):
    for path in sorted(glob.glob(os.path.join(IMG_DIR, "udp-n*.png"))):
        print(path)


def run_rate(args):
    print(rate_one(args.csv_path, args.window, args.xmin, args.xmax, args.log))


def run_rate_all(args):
    pattern = CONCENTRATED_DATASET_PATTERN if args.csgnbat else DATASET_PATTERN
    dfs = {}
    for n in ATTACKER_COUNTS:
        matches = sorted(glob.glob(pattern.format(n=n)))
        if not matches:
            print(f"skip (not found): {pattern.format(n=n)}", file=sys.stderr)
            continue

        csv_path = matches[0]
        dfs[csv_path] = compute_rate_df(csv_path, args.window)

    if not dfs:
        sys.exit("No labeled CSVs found in datasets/; nothing was plotted.")

    ylim = shared_ylim(dfs.values(), args.xmin, args.xmax, args.log)

    for csv_path, df in dfs.items():
        print(render_rate_plot(df, csv_path, args.xmin, args.xmax, args.log, ylim=ylim))


def compute_rate_df(csv_path, window):
    byte_sums = {}
    for chunk in pd.read_csv(csv_path, usecols=["frame.time_epoch", "frame.len", "label"], chunksize=PLOT_CHUNK_SIZE):
        chunk["bin"] = (chunk["frame.time_epoch"] // window).astype(int)
        for (label, b), s in chunk.groupby(["label", "bin"])["frame.len"].sum().items():
            byte_sums[(label, b)] = byte_sums.get((label, b), 0) + s
        del chunk
    gc.collect()

    if not byte_sums:
        sys.exit(f"No rows found in {csv_path}")

    return pd.DataFrame(
        [{"label": l, "time_s": b * window, "throughput_mbps": (s * 8) / (window * 1e6)}
         for (l, b), s in byte_sums.items()]
    )


def shared_ylim(dfs, xmin, xmax, log):
    all_rates = []
    for df in dfs:
        windowed = df[(df["time_s"] >= xmin) & (df["time_s"] <= xmax)]
        all_rates.extend(windowed["throughput_mbps"].tolist())

    if not all_rates:
        return None

    if log:
        positive = [r for r in all_rates if r > 0]
        return (min(positive), max(positive) * 2.4) if positive else None

    lo, hi = min(all_rates), max(all_rates)
    span = (hi - lo) if hi > lo else max(hi, 1.0)
    top_pad = span * 0.23
    return (0.0, hi + top_pad)


def render_rate_plot(df, csv_path, xmin, xmax, log, ylim=None):
    plt.rcParams["font.family"] = "serif"
    plt.rcParams["font.serif"] = ["Times New Roman", "Liberation Serif", "DejaVu Serif"]

    FONT_SIZE = 23

    plot_df = df[(df["time_s"] >= xmin) & (df["time_s"] <= xmax)]

    fig, ax = plt.subplots(figsize=(9, 5))

    for label, color in [("normal", "#00A86B"), ("attack", "#8E44AD")]:
        sub = plot_df[plot_df["label"] == label].sort_values("time_s")
        if len(sub):
            ax.plot(sub["time_s"], sub["throughput_mbps"], color=color, linewidth=1.3, label=label.capitalize())

    ax.axvline(100, color="firebrick", linestyle="--", linewidth=1.8, label="Attack Start")

    if log:
        ax.set_yscale("log")
    ax.set_ylabel("Throughput [Mbps]", fontsize=FONT_SIZE)

    if ylim is not None:
        ax.set_ylim(*ylim)

    ax.set_xlabel("Time [s]", fontsize=FONT_SIZE)
    ax.set_xlim(xmin, xmax)
    ax.tick_params(axis="both", which="major", labelsize=FONT_SIZE, width=2.2, length=8)
    ax.tick_params(axis="both", which="minor", width=2.2, length=5)

    ax.xaxis.set_major_locator(MultipleLocator(10))
    if not log:
        ax.yaxis.set_major_locator(MaxNLocator(nbins=14))
    else:
        ax.yaxis.set_minor_locator(LogLocator(base=10.0, subs="all"))
        ax.grid(True, axis="y", which="minor", linestyle="-", linewidth=0.4, color="gray", alpha=0.4)
    ax.grid(True, axis="both", which="major", linestyle="-", linewidth=0.6, color="gray", alpha=0.6)
    legend = ax.legend(loc="upper left", fontsize=FONT_SIZE, framealpha=1, fancybox=False, handlelength=1.6, handletextpad=0.6)
    legend.get_frame().set_linewidth(2.6)
    legend.get_frame().set_edgecolor("black")
    for spine in ax.spines.values():
        spine.set_linewidth(2.2)
        spine.set_edgecolor("black")

    plt.tight_layout()
    tag = tag_from_csv(csv_path)
    tag_match = re.match(r"^(n\d+)-(dmgnbat|csgnbat)$", tag)
    out_tag = f"{tag_match.group(1)}-{tag_match.group(2)}" if tag_match else tag
    out_path = os.path.join(IMG_DIR, f"udp-{out_tag}.png")
    os.makedirs(IMG_DIR, exist_ok=True)
    plt.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def rate_one(csv_path, window, xmin, xmax, log):
    df = compute_rate_df(csv_path, window)
    ylim = shared_ylim([df], xmin, xmax, log)
    return render_rate_plot(df, csv_path, xmin, xmax, log, ylim=ylim)


def run_compare(args):
    """Average attack throughput versus attacker count for both topologies."""
    series = {}
    for label, pattern in [("DMgNBAT", REPORT_PATTERN),
                           ("CSgNBAT", CONCENTRATED_REPORT_PATTERN)]:
        rows = [build_row(n, pattern) for n in ATTACKER_COUNTS]
        rows = [r for r in rows if r is not None]
        if not rows:
            sys.exit(f"No results found for {label}.")
        series[label] = pd.DataFrame(rows).sort_values("attackers")

    os.makedirs(IMG_DIR, exist_ok=True)

    with plt.rc_context({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Nimbus Roman", "Liberation Serif", "DejaVu Serif"],
        "mathtext.fontset": "stix",
        "font.size": 14,
        "figure.facecolor": "white",
        "axes.facecolor": "white",
    }):
        fig, ax = plt.subplots(figsize=(6.0, 3.8))

        styles = {
            "DMgNBAT": dict(color="#1f77b4", marker="o", linestyle="-"),
            "CSgNBAT": dict(color="#ff7f0e", marker="s", linestyle="--"),
        }

        for label, df in series.items():
            ax.errorbar(df["attackers"],
                        df["attack_throughput_mbps_mean"],
                        yerr=df["attack_throughput_mbps_std"],
                        capsize=3, linewidth=1.6, markersize=6,
                        label=label, **styles[label])

        ax.set_xlabel("Number of compromised devices ($N_{atk}$)")
        ax.set_ylabel("Average attack throughput (Mbps)")
        ax.set_xlim(1.6, 10.4)
        ax.set_xticks(ATTACKER_COUNTS)
        ax.set_ylim(0, 38)
        ax.set_yticks(range(0, 36, 5))
        leg = ax.legend(loc="upper right", frameon=True, edgecolor="black",
                        framealpha=1.0, fancybox=False)
        leg.get_frame().set_linewidth(0.8)
        ax.grid(True, color="0.8", linestyle="-", linewidth=0.6)
        ax.set_axisbelow(True)
        fig.tight_layout()

        out = os.path.join(IMG_DIR, "attack_throughput_comparison.pdf")
        fig.savefig(out, bbox_inches="tight")
        plt.close(fig)

    print(f"saved {out}")
    for label, df in series.items():
        print(f"\n{label}:")
        print(df[["attackers", "attack_throughput_mbps_mean",
                  "attack_throughput_mbps_std"]].to_string(index=False))


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)

    p_table = sub.add_parser("table")
    p_table.add_argument("--skip-run", action="store_true")
    p_table.add_argument("--max-mem-pct", type=int, default=DEFAULT_MAX_MEM_PCT)
    p_table_mode = p_table.add_mutually_exclusive_group(required=True)
    p_table_mode.add_argument("--dmgnbat", action="store_true",
                               help="Distributed Multi-gNB Attack Topology")
    p_table_mode.add_argument("--csgnbat", action="store_true",
                               help="Concentrated Single-gNB Attack Topology")

    p_rate = sub.add_parser("throughput")
    p_rate.add_argument("csv_path")
    p_rate.add_argument("--window", type=float, default=0.1, help="time bin size in seconds")
    p_rate.add_argument("--xmin", type=float, default=60)
    p_rate.add_argument("--xmax", type=float, default=140)
    p_rate.add_argument("--log", action="store_true", default=True)
    p_rate.add_argument("--no-log", dest="log", action="store_false")

    p_rate_all = sub.add_parser("throughput-all")
    p_rate_all.add_argument("--window", type=float, default=0.1)
    p_rate_all.add_argument("--xmin", type=float, default=60)
    p_rate_all.add_argument("--xmax", type=float, default=140)
    p_rate_all.add_argument("--log", action="store_true", default=True)
    p_rate_all.add_argument("--no-log", dest="log", action="store_false")
    p_rate_all_mode = p_rate_all.add_mutually_exclusive_group(required=True)
    p_rate_all_mode.add_argument("--dmgnbat", action="store_true",
                                  help="Distributed Multi-gNB Attack Topology")
    p_rate_all_mode.add_argument("--csgnbat", action="store_true",
                                  help="Concentrated Single-gNB Attack Topology")

    sub.add_parser("compare")
    sub.add_parser("list")

    args = parser.parse_args()
    if args.mode == "table":
        run_table(args)
    elif args.mode == "compare":
        run_compare(args)
    elif args.mode == "list":
        run_list(args)
    elif args.mode == "throughput":
        run_rate(args)
    elif args.mode == "throughput-all":
        run_rate_all(args)


if __name__ == "__main__":
    main()
