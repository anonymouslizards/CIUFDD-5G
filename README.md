# CIUFDD-5G
Configurable IoT UDP Flood DDoS Dataset for 5G


Tested on Ubuntu 24.04.4 LTS with ns-3.40, 5G-LENA v2.6.y, Python 3.12.3
and TShark 4.6.6.

## 1. Create the working directory

Any directory works. The examples below use `~/ciufdd-5g`.

    mkdir -p ~/ciufdd-5g
    cd ~/ciufdd-5g

## 2. Install the system packages

    sudo apt update

    sudo apt install -y g++ python3 python3-dev python3-pip python3-venv \
      cmake ninja-build git pkg-config \
      libc6-dev sqlite3 libsqlite3-dev libeigen3-dev \
      libxml2 libxml2-dev libboost-all-dev \
      gdb valgrind tshark

## 3. Clone ns-3 and 5G-LENA

    git clone https://gitlab.com/nsnam/ns-3-dev.git
    cd ns-3-dev
    git checkout -b ns-3.40 ns-3.40

    cd contrib
    git clone https://gitlab.com/cttc-lena/nr.git
    cd nr
    git checkout -b 5g-lena-v2.6.y origin/5g-lena-v2.6.y

## 4. Build

    cd ~/ciufdd-5g/ns-3-dev
    ./ns3 configure -d optimized --disable-examples --disable-tests
    ./ns3 build

Check that the NR module was built and that the demo runs:

    ./ns3 show targets | grep nr
    ./ns3 run cttc-nr-demo

## 5. Set up Python

    python3 -m venv venv
    source venv/bin/activate
    pip install pandas matplotlib numpy

## 6. Place the files

Put `ciufdd-5g.cc` in `scratch/`.

Put `labeling.py` and `plot.py` in `scripts/`.

    mkdir -p scripts

## 7. Quick check

Before running the full sweep, a single configuration confirms that the
build and the scripts work end to end. This takes a few minutes.

    ./ns3 run "ciufdd-5g --dmgnbat --attackers=3 --RngRun=1"
    source venv/bin/activate
    python3 scripts/labeling.py --dmgnbat

This produces one PCAP under `pcaps/`, one report under `txt/` and one
labeled CSV under `datasets/`.

## 8. Run the full sweep

Each topology runs nine attacker counts for each of five seeds, that is
45 simulations per topology and 90 in total. On the machine used for the
paper this took about 15 hours for DMgNBAT and 11 hours for CSgNBAT,
averaging roughly 18 minutes per simulation. An optimized build, as
configured in step 4, is faster than the default profile used there.

DMgNBAT, full sweep, five seeds:

    for seed in 1 2 3 4 5; do
      ./ns3 run "ciufdd-5g --dmgnbat --RngRun=$seed"
    done

CSgNBAT, full sweep, five seeds:

    for seed in 1 2 3 4 5; do
      ./ns3 run "ciufdd-5g --csgnbat --RngRun=$seed"
    done

## 9. Label the captures

Activate the virtual environment first.

    source venv/bin/activate
    python3 scripts/labeling.py --dmgnbat
    python3 scripts/labeling.py --csgnbat

## 10. Generate the tables

    python3 scripts/plot.py table --dmgnbat --skip-run
    python3 scripts/plot.py table --csgnbat --skip-run

## 11. Generate the figures

One throughput figure per attacker count:

    python3 scripts/plot.py throughput-all --dmgnbat
    python3 scripts/plot.py throughput-all --csgnbat

Comparison figure for both topologies:

    python3 scripts/plot.py compare

## Selecting the topology and the attacker count

The topology flag selects the attacker placement. The attacker count is
optional. Without `--attackers`, the full sweep from 2 to 10 is executed.
If no topology flag is given, DMgNBAT is used by default.

    ./ns3 run "ciufdd-5g --dmgnbat --attackers=3"
    ./ns3 run "ciufdd-5g --csgnbat --attackers=3"

Without `--RngRun`, the default seed is 1, so the output files are written
as `run1` and overwrite any existing files with that seed.
