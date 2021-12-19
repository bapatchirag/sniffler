# Sniffler

Simple Python-based packet sniffer, complete with a GUI interface for easy viewing and analysis.

## Progress

- [x] Basic operation
  - [x] Protocol based packet filters for display
- [ ] Command line integration
- [ ] Add support for more protocols
- [ ] GUI

## Requirements

- ```python3```
- ```argparse``` module, install from pip as:
  ```bash
  pip3 install argparse
  ```

## Usage

Currently, run as administrator as:
```bash
sudo python3 sniffler.py
```

For filtering of packet types, use ```--filter``` option followed by protocol list

### Protocols supported
- [x] TCP segments (IPv4)
- [x] Ethernet frames
- [x] UDP segments (IPv4)
- [ ] ICMP 