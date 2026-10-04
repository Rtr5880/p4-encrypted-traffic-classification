# Manual RF-C demonstration

Use Ubuntu/WSL for all commands. The working directory is
`/home/geleza/p4/etc-training`. T1 runs BMv2 continuously and T2 remains at
`RuntimeCmd:`. T3 runs the packet sender. The normal live program uses BMv2's
ingress clock and records decisions in `FeatureIngress.rf_decisions`.

## The three-terminal arrangement

| Terminal | Role |
|---|---|
| T1 | Running RF-C BMv2, port1 on p1_sw1 and port2 on p1_sw2 |
| T2 | CLI on management port9090; inspect ports and class counters |
| T3 | Send and capture a small bidirectional UDP flow |

The virtual cable pairs are p1_host1/p1_sw1 and p1_sw2/p1_host2.
Forward packets enter host1 and emerge at host2; reverse packets take the
opposite path. The sender swaps both IP addresses and UDP ports, keeping them
in the same bidirectional flow. No IP addresses need to be assigned to the
interfaces because Scapy constructs and transmits complete Ethernet frames.

## Inspect the sender before using it

In T3:

```bash
cd /home/geleza/p4/etc-training
code /home/geleza/p4/etc-training/tools/manual_rf_demo.py

/home/geleza/p4/bmv2-venv/bin/python \
  /home/geleza/p4/etc-training/tools/manual_rf_demo.py \
  --packets 7 --source-port 47107 --dry-run
```

`packet_plan` defines directions, addresses, ports and sizes. `make_frame`
builds Ether/IP/UDP/payload headers. `CaptureCheck` verifies each packet at the
sending and receiving host interfaces, matching its unique run marker and exact
bytes. `main` arms both capture interfaces before sending.

The dry run prints the plan without transmitting or capturing traffic. The live
sender uses the existing bmv2-venv because Scapy is installed there; activating
a venv in the shell is unnecessary when its Python path is explicit.

## Run the first case: seven packets

In T3:

```bash
cd /home/geleza/p4/etc-training
sudo /home/geleza/p4/bmv2-venv/bin/python \
  /home/geleza/p4/etc-training/tools/manual_rf_demo.py \
  --packets 7 --source-port 47107
```

`sudo` permits raw Ethernet transmission/capture. All seven packets belong to
one flow between 10.254.0.1:47107 and 10.254.0.2:443. They alternate forward and
reverse, with IPv4 lengths120,140,160 bytes. Port443 is just a demo transport
port; the synthetic payload has no voice/video activity ground truth.

Expected capture outcome:

```text
Observed outbound: 7/7; forwarded: 7/7
FORWARDING: PASS
```

The switch forwards these packets, while classification waits for packet8.
Return to T2 and read all six counters:

```text
counter_read FeatureIngress.rf_decisions 0
counter_read FeatureIngress.rf_decisions 1
counter_read FeatureIngress.rf_decisions 2
counter_read FeatureIngress.rf_decisions 3
counter_read FeatureIngress.rf_decisions 4
counter_read FeatureIngress.rf_decisions 5
```

On the initial clean demo, all six packet counts should still be zero. These
commands belong at `RuntimeCmd:` and must not be entered at the Bash prompt.

## Follow with eight and twelve packets

Once the first result is confirmed, use the following T3 commands in order.
Read the six T2 counters after each invocation.

```bash
cd /home/geleza/p4/etc-training
sudo /home/geleza/p4/bmv2-venv/bin/python \
  /home/geleza/p4/etc-training/tools/manual_rf_demo.py \
  --packets 8 --source-port 47108
```

```bash
cd /home/geleza/p4/etc-training
sudo /home/geleza/p4/bmv2-venv/bin/python \
  /home/geleza/p4/etc-training/tools/manual_rf_demo.py \
  --packets 12 --source-port 47112
```

| Case | Forwarded packets expected | New RF decisions expected | Total after the three cases |
|---|---:|---:|---:|
| Seven, sourceport47107 | 7 | 0 | 0 |
| Eight, sourceport47108 | 8 | 1 | 1 |
| Twelve, sourceport47112 | 12 | 1 | 2 |

Sum the packet fields across the six counters. Either classified flow can select
any class; live timing changes the IAT values. If both select the same class,
one counter can end at2. If they select different classes, two counters end at1.

Class indices are0 CHAT,1 FT,2 MAIL,3 P2P,4 STREAMING,5 VOIP.

Use each sourceport once in a demo. Reusing it can continue an existing instance
within the 60-second idle period. Choose a fresh port for a repeat, or restart
your foreground BMv2 process and reconnect the CLI for a clean demonstration.
`counter_reset` clears counter observations but does not reset the flow state.

## Evidence and interpretation

Each live sender run prints a unique directory beneath
`/home/geleza/p4/etc-training/results/manual_rf_demo`. It contains the packet
plan, captured sent/received PCAPs and a forwarding summary. Capture files keep
arrival order, and new evidence is assigned to the invoking student's account
when the script is run through sudo.

The forwarding summary checks exact packet bytes and excludes unrelated traffic
using a unique payload marker. It does not read RF counters or compute model
predictions. Save the T2 counter readings alongside the sender output to show
classification timing.

This demonstration establishes live forwarding and when the switch classifies.
The existing synthetic test suite established feature/leaf/score/prediction
parity. Real capture replay and activity-labelled accuracy evaluation are the
next separate evidence to collect.

## Sender checks

The following command exercises flow mapping and capture verification without
sending traffic or starting another switch:

```bash
cd /home/geleza/p4/etc-training
/home/geleza/p4/bmv2-venv/bin/python -m unittest discover \
  -s tools -p 'test_manual_rf_demo.py'
```

Eight checks pass, including one that prevents outbound-only captures from being
reported as successful forwarding. The frame-construction check uses Scapy from
bmv2-venv; discovery under an environment without Scapy skips that one check.
