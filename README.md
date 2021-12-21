# Sniffler

Simple Python-based packet sniffer, complete with a GUI interface for easy viewing and analysis.

## Progress

- [x] Basic operation
  - [x] Protocol based packet filters for display
- [ ] Command line integration (TBD)
- [ ] Add support for more protocols (TBD)
- [ ] Modularise CLI to allow for GUI integration with same modules
- [ ] GUI
  - [x] UI
  - [ ] Actions
    - [ ] Table population
    - [ ] Population prerequisite/post-population filtering
    - [ ] Analysis (packet counts, insecure packet counts, maybe more?)
    - [ ] Error handling

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

For filtering of packet types, use ```-f``` or ```--filter``` option followed by protocol list

### Example usage
- All packets
  ```bash
  sudo python3 sniffler.py
  ```
- Filter only tcp segments
  ```bash
  sudo python3 sniffler.py -f tcp
  ```
- Filter ethernet frame info and tcp segments
  ```bash
  sudo python3 sniffler.py --filter tcp eth
  ```
- Help
  ```bash
  sudo python3 sniffler.py --help
  ```

### Protocols supported
- [x] TCP segments (IPv4) - tcp
- [x] Ethernet frames - eth
- [x] UDP segments (IPv4) - udp
- [ ] ICMP - icmp