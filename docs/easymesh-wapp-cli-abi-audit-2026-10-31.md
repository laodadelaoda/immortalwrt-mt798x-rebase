# N60 Pro WAPP command-line ABI audit

Date: 2026-10-31

Repository branch: `n60pro-mtk-closed-driver`

## Scope

This audit covers the tracked WAPP executable, its N60 wrapper, and the MAP configuration hand-off. It does not change the WAPP binary, DAT files, WTS contents, MAPD/P1905 configuration values, radio driver, or EasyMesh process topology.

## Binary evidence

Tracked executable:

- `package/mtk/applications/easymesh-n60/files/usr/bin/wapp`
- ELF: 64-bit AArch64
- Size observed during audit: 1,044,659 bytes
- Embedded `getopt()` option string: `m:f:i:d:v:e:w:k:c:F:u:`

The option string was extracted directly from the tracked binary. The option parser and its switch cases were cross-checked against the MediaTek WAPP `main.c` mirror at:

- https://github.com/RMerl/asuswrt-merlin.ng/blob/7048222b452420a9fb9ce5960d13fe289fb16c5a/release/src/router/wapp/source/common/main.c

The mirror contains the same `getopt()` option string and matching option handlers. This is an ABI cross-reference; it does not claim that the mirror is the exact source archive used to produce this binary.

## Supported option mapping

| Option | Handler / meaning | N60 Pro use |
|---|---|---|
| `-m` | WAPP operation mode | `OPMODE_AP` |
| `-i` | Driver IPC mode | `RA_WEXT` |
| `-d` | WAPP debug level | `1` |
| `-v` | WAPP interface/version selector | `2` |
| `-f` | WAPP AP configuration-list file | `/etc/wapp_ap.conf` |
| `-F` | MAP configuration file | `/etc/map/mapd_cfg` |
| `-u` | MAP user configuration file | `/etc/map/mapd_user.cfg` |
| `-e` | IAPP Ethernet interface | `br-lan` |
| `-w` | IAPP WLAN-side control interface | `br-lan` |
| `-c` | Repeated IAPP wireless ioctl interface | `ra0`, then `rax0` |
| `-k` | IAPP security key | Omitted; retain the binary's compiled default |

The vendor header defines the IAPP Ethernet and WLAN-side defaults as `br0` for its OpenWrt build. N60 Pro uses `br-lan`, so the wrapper explicitly maps both bridge-facing IAPP fields to `br-lan`.

The IAPP ioctl list is separate: the source handler appends each `-c` value to `IfNameWlanIoctl[]`. Two entries are supplied for the N60 Pro radios. The first default slot is overwritten by `ra0`; the second entry is `rax0`.

## Unsupported options and prior failure

- `-l` is absent from the embedded option string. The parser sends it to the unknown-option branch and returns an error.
- Uppercase `-K` is absent. It is not an alias for lowercase `-k`.
- Lowercase `-k` is the IAPP security key, not a P1905 configuration-file argument. Passing `/etc/map/1905d.cfg` to `-k` would be semantically wrong.
- The P1905 daemon independently receives its configuration through its own `-f /etc/map/1905d.cfg` argument in the init service. WAPP does not need a `-K` argument for that file.
- The source switch contains a `case 'h'`, but `h` is absent from the getopt option string; do not rely on `-h` or `--help` as a valid diagnostic mode.

The previous wrapper therefore failed during WAPP argument parsing before normal MAP/WAPP initialization could proceed.

## WAPP radio discovery versus IAPP ioctl registration

These are distinct mechanisms:

1. `-c ra0 -c rax0` populates the IAPP ioctl-interface list used to query wireless interface MAC addresses.
2. WAPP radio-device discovery is performed by `wapp_get_wireless_interfaces()`. It reads `bss_config_priority` from the MAP configuration; if that value is empty, the source falls back to dynamic enumeration of `/proc/net/dev` and tests wireless interfaces with `SIOCGIWNAME`.
3. AP configuration loading is a third path: `-f /etc/wapp_ap.conf` opens the file, and `wapp_init_all_config()` parses its `conf_list` and invokes AP configuration initialization for each listed band file.

Consequently, the repeated `-c` options must not be described as setting WAPP's MAP radio-discovery list. The WAPP `-F` input is `/etc/map/mapd_cfg`; its deterministic N60 radio list is `bss_config_priority=ra0;rax0`. The separate P1905 `1905d.cfg` retains its own independently consumed list.

## Corrected N60 Pro invocation

```sh
/usr/bin/wapp -m OPMODE_AP -i RA_WEXT -d 1 -v 2 \
    -f /etc/wapp_ap.conf \
    -F /etc/map/mapd_cfg \
    -u /etc/map/mapd_user.cfg \
    -e br-lan -w br-lan \
    -c ra0 -c rax0
```

## CI regression guard

The N60 build workflow now checks:

- the WAPP executable contains the audited option string;
- the wrapper passes the expected AP/WEXT, config, bridge, and dual-radio arguments;
- unsupported `-l` and `-K` options do not reappear.

This check validates the static command-line contract. It does not replace runtime validation of WAPP process startup or EasyMesh/WTS event flow on the router.
