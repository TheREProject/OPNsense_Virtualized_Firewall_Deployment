# Virtualizing OPNsense: Deploying a Software Router/Firewall on Proxmox

## Overview

This documents deploying [OPNsense](https://opnsense.org/) as a virtualized firewall/router under Proxmox, replacing a consumer-grade router that sat between two internal LAN segments and the upstream internet gateway (which was never touched). The install itself was straightforward; getting it running *correctly* took four separate issues, each diagnosed and resolved in turn — including one where the fix for one problem quietly reintroduced another.

## Environment

- Proxmox VE (hypervisor)
- OPNsense (virtualized firewall/router), 32GB VM disk
- 2-port NIC, one Linux bridge (vmbr) per physical port, mapped 1:1 — no other VM has access to either port
- Existing topology: upstream router (untouched) → OPNsense → downstream router/LAN segment

## Objective

Replace a consumer/gaming-grade router with a purpose-built firewall/router offering real VPN and security capabilities, without disturbing the actual internet gateway further upstream.

## Design Decision: Bridged NICs Instead of PCI Passthrough

The original plan called for PCI passthrough, giving OPNsense direct, exclusive hardware access to each NIC port for the best possible performance. In practice, Proxmox's VM network configuration required selecting a bridge, so each of the NIC's two physical ports was given its own dedicated Linux bridge (vmbr) instead — each bridge mapped 1:1 to a single physical port, with no other VM (including the TrueNAS host) ever attached to either one.

This wasn't a fallback forced by a hardware limitation — it was a deliberate tradeoff to keep 802.1Q VLAN trunking testing possible in the future, something true passthrough would complicate. Passthrough is still recognized as the better option for raw performance and remains a candidate upgrade later, once there's an actual need for it.

## The Plan

1. Back up the existing Proxmox configuration.
2. Gather OPNsense's system requirements.
3. Download the OPNsense image and verify its authenticity before ever booting it.
4. Plan the subnet layout.
5. Allocate VM disk size (32GB).
6. Upload the image to Proxmox and create the VM, pointing the designated physical NIC's bridge at it.
7. Install and configure OPNsense, skipping LAGG/VLAN setup (not needed for this deployment) and setting the WAN interface to DHCP, since it sits below the existing router/modem.
8. Test connectivity and internet access during off-hours, then verify bandwidth against the previous router.

### Image Verification

Because this is networking infrastructure that all downstream traffic depends on, the OPNsense image was verified before deployment rather than taken on faith — using OpenSSL against the published checksum, detached signature, and OpenSSL public key from an official mirror. Critically, the public key itself was cross-checked against a second, independent source (OPNsense's own package-mirror README) rather than trusted from the same download as everything else: if a mirror were compromised, it could serve a matching-but-malicious key alongside a malicious image, and trusting a single source for everything would defeat the point of verifying at all. Full steps: [OPNsense's own download-and-verification guide](https://docs.opnsense.org/manual/install.html#download-and-verification).

This process was turned into a small **PowerShell GUI tool** to make it fast and consistent to repeat on every future major-version upgrade, rather than something that quietly gets skipped for convenience after the first time.

## What Went Wrong

Four distinct issues surfaced after the initial install — not because the plan was wrong, but because virtualized network appliances have failure modes a physical router simply doesn't.

### 1. OPNsense's GUI Was Unreachable After IP Configuration

**Investigation:** Devices behind OPNsense (on its LAN side) were still reachable, firewall rules permitting — so the network path itself wasn't broken, which narrowed this to something specific to OPNsense's own management access.

**Root cause:** The LAN IP address had been configured on the Proxmox bridge (vmbr) itself, not inside OPNsense. Two different layers can both "own" an IP-looking configuration when virtualizing a network appliance, and this one landed on the wrong side of that line.

**Fix:** Removed the address from the Proxmox bridge and configured it correctly inside OPNsense.

### 2. No Internet Access

**Investigation:** OPNsense's own gateway was reachable, which meant the problem was downstream of it rather than in OPNsense itself. Checking the downstream router's routing table showed its default route was still pointing at the old router's address — a leftover from before the swap.

**Fix:** Updated the downstream router's default route to point at OPNsense. Internet access returned immediately.

### 3. Bandwidth Dropped to ~20–30% of Normal

**Investigation:** This one needed real isolation work. Bandwidth *between* devices on the downstream LAN was near full speed, but anything crossing OPNsense to reach the internet wasn't — confirmed by running speed tests from the untouched upstream router (full bandwidth) versus from behind OPNsense (~20–30%), which pointed squarely at the OPNsense hop itself rather than the ISP connection or the downstream router. A self-hosted `iperf3` server on OPNsense, tested from both the downstream router and client machines, confirmed the same degraded numbers.

From there: hardware checksum/segmentation offloading was confirmed disabled (OPNsense's default), and cross-referencing OPNsense's own documentation ruled out a misconfiguration elsewhere. The actual lever turned out to be one layer down — Proxmox's own documentation notes that its default emulated NIC model (Intel E1000) carries real overhead compared to the paravirtualized VirtIO driver.

**Fix:** Switched the VM's virtual NIC model from E1000 to VirtIO. Bandwidth returned to normal — though that wouldn't be confirmed until the next issue was resolved, since the fix immediately triggered a new failure.

### 4. Internet Access Failed Again After the VirtIO Change

**Investigation:** This was the hardest of the four to pin down. Using OPNsense's own Diagnostics → Ping/Traceroute tools: the downstream router's WAN address was reachable from clients, and OPNsense's LAN address was reachable — but OPNsense's *own* LAN-side address couldn't reach its *own* WAN-side address. Any packet trying to go upstream was failing before it ever left the box. Interestingly, pinging out from OPNsense's WAN port directly worked fine — the problem was specifically traffic originating from the LAN side.

A first fix — the LAN interface had its own gateway configured, when only the WAN interface should — was correct in principle (this came from forum research into similar OPNsense multi-WAN symptoms) but didn't fully resolve it on its own.

**Fix:** Rather than keep layering incremental changes onto an already-uncertain configuration, the OPNsense install was factory-reset and rebuilt from a specific, written procedure:

1. Assign interfaces: `vtnet0` → WAN, `vtnet1` → LAN, no optional ports.
2. WAN: DHCP, no IPv6.
3. LAN: static IP, no IPv6, **no upstream gateway configured on the LAN interface**, DHCP server enabled for the LAN scope.
4. Set DNS to resolve via the LAN interface.
5. Unchecked **"Optimize for multi-WAN"** — a setting that changes routing/gateway-selection behavior and doesn't belong on a single-WAN setup.

Internet access returned. To make sure this wasn't a fluke, the entire reset-and-rebuild process was repeated from scratch a second time, following the same written procedure — and it succeeded cleanly again. Only after that reproducibility check did the working configuration get restored and trusted as the real fix, rather than the first one that happened to work once.

## Result

- Internet access and full inter-LAN connectivity confirmed stable across both downstream and upstream segments, with the actual internet gateway untouched throughout.
- Bandwidth restored to expected levels after the E1000 → VirtIO change, verified with the same `iperf3` methodology used to diagnose the original drop.
- The fix for the recurring internet-access failure was validated by reproducing the entire factory-reset-and-rebuild procedure a second time to a clean success, not just trusted after a single working attempt.
- A reusable, written OPNsense deployment procedure now exists for any future rebuild, along with a small PowerShell tool that makes image verification a consistent step rather than an easily-skipped one.

## Lessons Learned

### 1. Virtualizing a network appliance splits configuration across two layers

An IP address, a NIC model, a bridge — any of these can be set at the hypervisor layer or inside the guest OS, and they're easy to conflate. The unreachable-GUI issue happened because a setting landed on the wrong side of that line, not because either layer was misconfigured on its own terms.

### 2. Replacing a device doesn't clean up what depended on it

The downstream router's stale default route wasn't OPNsense's fault — it was leftover state on a *different* device that nobody had reason to touch until traffic actually broke. Any device swap needs an audit of what else was pointed at the old one.

### 3. Default virtual NIC emulation has a real, measurable cost

E1000 emulation versus VirtIO wasn't a marginal difference — it was the entire gap between ~20–30% and full bandwidth. Worth checking the NIC driver model first, not last, on anything virtualized and performance-sensitive.

### 4. A fix that's "correct" isn't the same as a fix that's "sufficient"

The LAN-gateway correction was the right call based on the forum research, and it still wasn't enough by itself. Rather than keep patching an increasingly uncertain state, a clean rebuild from a written procedure turned out to be faster and more trustworthy than continuing to debug forward.

### 5. A fix isn't proven until it's reproduced

Getting internet access back once could have been coincidence, timing, or an unrelated change clearing itself. Repeating the entire procedure from a factory reset and getting the same clean result a second time is what actually turned "it's working now" into "this is the fix."

### 6. Security steps survive only if they're made easy to repeat

Image verification is easy to justify once and skip the next five times unless it's frictionless. Wrapping it in a small PowerShell GUI tool was a deliberate bet that future-self will actually use it every time, not just this once.

## Useful Commands & Tools

```text
# Image verification (OpenSSL) — general pattern per OPNsense's own guidance
openssl dgst -sha256 <image-file>                                  # compute checksum, compare to <file>.sha256
openssl dgst -sha256 -verify <public-key.pub> -signature <file.sig> <image-file>   # verify signature

# Bandwidth diagnosis
iperf3 -s                          # hosted on OPNsense
iperf3 -c <opnsense-address>       # run from downstream router / client machines

# OPNsense GUI tools used (Diagnostics menu)
Ping                                # confirm reachability hop by hop
Traceroute                          # confirm path and where it breaks

# Interface assignment during OPNsense setup
vtnet0 -> WAN
vtnet1 -> LAN
```

## Infrastructure / IT Skills Demonstrated

- Virtualized network appliance deployment (Proxmox + OPNsense)
- Virtual NIC driver/performance tuning (emulated E1000 vs. paravirtualized VirtIO)
- Systematic bandwidth diagnostics using comparative baselines and `iperf3`
- Multi-hop routing and gateway troubleshooting across a real network topology
- Software firewall/router configuration (WAN/LAN interface roles, DHCP, IPv6 scoping decisions)
- Security hygiene: firmware/image checksum and signature verification before deployment, including independently verifying the public key itself
- Disciplined incident methodology: isolate → hypothesize → test → validate reproducibility, rather than stopping at "it works now"
- PowerShell GUI scripting for operational tooling
