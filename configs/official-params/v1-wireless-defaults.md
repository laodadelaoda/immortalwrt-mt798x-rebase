# N60 Pro / NX62 Official Wireless Defaults v1

Source: Netis NX62 V4.0.250611 official firmware
Files: mt7986-ax6000.dbdc.b0.dat / b1.dat
Extracted: 2026-10-24
Note: Linux 5.4 official firmware. Verify on Linux 6.12 before enabling.

## Official defaults

| Param | b0 (2.4G) | b1 (5G) | Current 10-01 b0 | Current 10-01 b1 | Action |
|---|---|---|---|---|---|
| SREnable | 1 | 1 | 1 | 1 | aligned |
| RRMEnable | 1 | 1 | 1 | 1 | aligned |
| TWTSupport | 1 | 1 | 0 | 0 | P1 mapping |
| DfsEnable | absent | 1 | absent | 0 | P1 mapping, 5G only |
| IEEE80211H | 1 | 1 | 0 | 1 | P1 mapping, verify b0 |
| FtSupport | 0 | 0 | 0 | 0 | P2, default off |
| BandSteering | 0 | 0 | 0 | 0 | P2, default off |
| VLANEn | absent | absent | absent | absent | P2, default off |
| PMFMFPC | 1 | 1 | 0 | 0 | do not copy blindly |
| KickStaRssiLow | absent | absent | 0 | 0 | official uses mapd APSteerRssiTh |

## Do not copy blindly

- CountryCode: official US, current CN. Keep CN.
- Channel: official fixed 6/36, current uses uci. Keep uci.
- PMFMFPC=1: official OPEN mode capability bit. Do not force PMF on WPA2 baseline without verification.

## P1 mapping targets

- TWTSupport: 0 -> 1
- DfsEnable: 0 -> 1 (5G only)
- IEEE80211H: b0 0 -> 1, b1 already 1

## P2 mapping targets

- FtSupport: default 0
- Dot11vMbssid: default 0
- BandSteering: default 0
- VLANEn: default 0
