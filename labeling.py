import argparse
import gc
import glob
import os
import re
import struct
import subprocess
import sys

import pandas as pd

OUTPUT_DIR = "datasets"
ATTACK_PORT = 5001
CHUNK_SIZE = 50000

TSHARK_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.time_delta",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "ip.ttl",
    "udp.srcport",
    "udp.dstport",
    "udp.length",
    "udp.payload",
]


def find_pcaps(mode_suffix: str) -> list:
    candidates = sorted(glob.glob(f"pcaps/udp-n*-{mode_suffix}-*.pcap"))
    if not candidates:
        sys.exit(f"No pcap file found in pcaps/ for {mode_suffix}")
    return candidates


def tag_to_labeled_name(tag: str) -> str:
    """udp-n2-dmgnbat-run3 -> udp-n2-labeled-dmgnbat-run3 (labeled goes right
    after the mode, before the run number, per the required naming
    convention). Also handles tags with no run suffix, for backward
    compatibility with files generated before --RngRun was added to every
    filename."""
    match = re.match(r"^(udp-n\d+)-(dmgnbat|csgnbat)(-run\d+)?$", tag)
    if not match:
        return f"{tag}-labeled"
    run_suffix = match.group(3) or ""
    return f"{match.group(1)}-labeled-{match.group(2)}{run_suffix}"


def tag_from_pcap(pcap_path: str) -> str:
    basename = os.path.basename(pcap_path)
    match = re.match(r"^(.+)-\d+-\d+\.pcap$", basename)
    return match.group(1) if match else basename.removesuffix(".pcap")


def decode_seq_ts(payload_hex: str):
    """Decodes ns-3's SeqTsHeader from the raw UDP payload.

    Verified against real pcap output: decoded delays are consistently sane
    (single- to double-digit ms for normal traffic, growing into the
    seconds range under attack saturation) and cross-checked arithmetically
    against the aggregate FlowMonitor delay figures.

    Byte layout:
      - first 4 bytes = sequence number (uint32, big-endian / network order)
      - next 8 bytes  = send timestamp in nanoseconds (int64, big-endian),
        matching ns-3's default Time::Resolution (NS)
    Returns (seq_num, send_time_ns), or (None, None) if the payload is
    missing, too short, or fails to parse.
    """
    if not isinstance(payload_hex, str) or len(payload_hex) < 24:
        return None, None
    try:
        payload_bytes = bytes.fromhex(payload_hex.replace(":", ""))
        seq_num = struct.unpack(">I", payload_bytes[0:4])[0]
        send_time_ns = struct.unpack(">q", payload_bytes[4:12])[0]
        return seq_num, send_time_ns
    except (ValueError, struct.error):
        return None, None


def run_tshark(pcap_path: str, csv_path: str) -> None:
    fields_args = []
    for field in TSHARK_FIELDS:
        fields_args += ["-e", field]

    cmd = [
        "tshark",
        "-r", pcap_path,
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
    ] + fields_args

    env = os.environ.copy()
    env["LC_NUMERIC"] = "C"
    env["LC_ALL"] = "C"

    with open(csv_path, "w") as out_file:
        result = subprocess.run(
            cmd, stdout=out_file, stderr=subprocess.PIPE, text=True, env=env
        )

    if result.returncode != 0:
        sys.exit(f"tshark failed:\n{result.stderr}")

    print(csv_path)


def label_dataset(raw_csv: str, labeled_csv: str) -> None:
    first_chunk = True

    for chunk in pd.read_csv(raw_csv, chunksize=CHUNK_SIZE):
        if chunk["frame.time_delta"].dtype == object:
            chunk["frame.time_delta"] = (
                chunk["frame.time_delta"].astype(str).str.replace(",", ".", regex=False).astype(float)
            )

        chunk["label"] = chunk["udp.dstport"].apply(lambda p: "attack" if p == ATTACK_PORT else "normal")

        decoded = chunk["udp.payload"].apply(decode_seq_ts)
        chunk["seq_num"] = decoded.map(lambda t: t[0])
        chunk["send_time_ns"] = decoded.map(lambda t: t[1])

        arrival_ns = chunk["frame.time_epoch"] * 1e9
        chunk["computed_delay_ms"] = (arrival_ns - chunk["send_time_ns"]) / 1e6

        for time_col in ("frame.time_epoch", "frame.time_delta"):
            chunk[time_col] = chunk[time_col].map(lambda x: f"{x:.9f}")

        chunk.to_csv(labeled_csv, mode="w" if first_chunk else "a", header=first_chunk, index=False)
        first_chunk = False

        del chunk
        gc.collect()

    print(labeled_csv)


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dmgnbat", action="store_true",
                       help="process Distributed Multi-gNB Attack Topology pcaps")
    mode.add_argument("--csgnbat", action="store_true",
                       help="process Concentrated Single-gNB Attack Topology pcaps")
    parser.add_argument("pcap_path", nargs="?", default=None,
                         help="optional: process only this specific pcap file "
                              "(mode flag is still required, for explicitness)")
    args = parser.parse_args()

    mode_suffix = "csgnbat" if args.csgnbat else "dmgnbat"

    if not os.path.isdir(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    pcaps = [args.pcap_path] if args.pcap_path else find_pcaps(mode_suffix)

    for pcap_path in pcaps:
        tag = tag_from_pcap(pcap_path)
        raw_csv = os.path.join(OUTPUT_DIR, f"{tag}.csv")
        labeled_csv = os.path.join(OUTPUT_DIR, f"{tag_to_labeled_name(tag)}.csv")
        run_tshark(pcap_path, raw_csv)
        label_dataset(raw_csv, labeled_csv)


if __name__ == "__main__":
    main()
