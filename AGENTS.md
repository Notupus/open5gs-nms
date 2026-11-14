# Antigravity Persistent System & Environment Rules

## 1. Execution Environment & Privileges
- **Host OS**: Fedora 45 (Linux kernel 6.x).
- **Host Access via nsenter**: The agent runs inside a container sandbox. To run commands directly on the host system (e.g. systemctl, ip, network config, compiling packages, inspecting host logs), ALWAYS use:
  `docker run --rm --privileged --pid=host alpine nsenter -t 1 -m -u -i -n -p -- <command>`
- **Git Repository & SSH Credentials**:
  - Main repository: `/opt/open5gs-nms`
  - GitHub Remote: `git@github.com:Notupus/open5gs-nms.git` (branch: `main`)
  - SSH key: `/home/npc/.ssh/key_rsa_ssh` (User: `Notupus`)
  - To push/fetch to GitHub:
    `GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no -i /home/npc/.ssh/key_rsa_ssh"`

## 2. Open5GS, IMS & Network Topology
- **PLMN**: MCC `202`, MNC `069`.
- **IMS Realm**: `ims.mnc069.mcc202.3gppnetwork.org`.
- **P-CSCF FQDN**: `pcscf.ims.mnc069.mcc202.3gppnetwork.org` -> Resolves to `10.46.0.1`.
- **TUN Interfaces & IP Subnets**:
  - `ogstun`: `10.45.0.1/16`, `2001:db8:cafe::1/48` (Default / Internet DNN).
  - `ogstun2`: `10.46.0.1/24`, `2001:db8:babe::1/48` (IMS DNN for VoLTE / VoNR).
  - Both TUN interfaces are brought up at boot via `/usr/local/sbin/open5gs-ogstun-up.sh` managed by `/etc/systemd/system/ogstun-setup.service` (`Before=open5gs-upfd.service open5gs-sgwud.service rtpengine-daemon.service kamailio-pcscf.service`).
  - Tracked in repo at `/opt/open5gs-nms/backup-restore/generate_open5gs_systemd.sh`.

## 3. Core Services & Critical Operational Details
- **BIND9 / DNS**:
  - Service unit on Fedora is `named.service` (aliased via `/etc/systemd/system/bind9.service -> /usr/lib/systemd/system/named.service`).
  - Zone file: `/etc/bind/zones/ims.mnc069.mcc202.3gppnetwork.org.zone`.
  - Listens on `10.46.0.1:53` and `127.0.0.1:53`.
- **RTPEngine**:
  - Built from source at `/opt/rtpengine-build/rtpengine-src/daemon` due to FFmpeg 9 (`libavcodec.so.63`) compatibility on Fedora 45 (do not overwrite with older FFmpeg 6 Debian/Ubuntu binaries).
  - Binary installed at `/usr/bin/rtpengine`.
  - Service: `rtpengine-daemon.service`.
  - Configuration: `/etc/rtpengine/rtpengine.conf` binds to `10.46.0.1:2223` (UDP NG control interface) on interface `ogstun2`.
- **Kamailio IMS Services**:
  - `kamailio-pcscf.service`: P-CSCF listening on `10.46.0.1:5060`.
  - `kamailio-icscf.service`: I-CSCF.
  - `kamailio-scscf.service`: S-CSCF.
  - `kamailio-smsc.service`: SMS over IMS.
- **PyHSS**:
  - Services: `pyhss-api`, `pyhss-diameter`, `pyhss-hss`, `pyhss-metrics`.
  - Provides Diameter Cx/Dx and Sh interfaces for Kamailio IMS AKA authentication.
- **Open5GS Core Network Functions (Host systemd)**:
  - `open5gs-amfd`, `open5gs-ausfd`, `open5gs-bsfd`, `open5gs-hssd`, `open5gs-mmed`, `open5gs-nrfd`, `open5gs-nssfd`, `open5gs-pcfd`, `open5gs-pcrfd`, `open5gs-scpd`, `open5gs-seppd`, `open5gs-sgwcd`, `open5gs-sgwud`, `open5gs-smfd`, `open5gs-udmd`, `open5gs-udrd`, `open5gs-upfd`.

## 4. Troubleshooting Known Issues
- **Pixel / UE VoNR/IMS Registration**:
  1. Verify UE requests and establishes PDU session for DNN `ims` on `ogstun2` (`10.46.0.0/24`).
  2. Verify SMF assigns DNS `10.46.0.1` via PCO to UE.
  3. Ensure UDP port 53 and 5060 are reachable on `ogstun2` (no firewall drops).
  4. Inspect SIP traffic via `tcpdump -ni ogstun2 -s0 -v port 5060 or port 53`.
  5. Check Kamailio P-CSCF logs (`journalctl -u kamailio-pcscf -e`) and PyHSS logs for SIP 401 Unauthorized / IMS-AKA response and IPsec SA negotiation.
