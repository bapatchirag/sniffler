# Sniffler

Simple Python-based packet sniffer, complete with a GUI interface for easy viewing and analysis.

## Progress

- [x] Basic operation
  - [x] Protocol based packet filters for display
- [ ] Command line integration (TBD)
- [ ] Add support for more protocols (TBD)
- [x] Modularise CLI to allow for GUI integration with same modules
- [x] GUI
  - [x] UI
  - [x] Actions
    - [x] Table population
    - [x] Pre-population filtering
    - [x] Analysis (packet counts, maybe more?)
    - [x] Status handling

## Requirements

- ```python3```
- ```argparse``` module, install from pip as:
  ```bash
  pip3 install argparse
  ```

## Usage

### CLI
Run CLI application as administrator as:
```bash
sudo python3 sniffler.py
```
#### Options
- For filtering by protocol, use ```-p``` or ```--proto``` option followed by protocol list
- For filtering by source address, use ```-sa``` or ```--srcaddr``` option followed by source address
- For filtering by source address, use ```-da``` or ```--dstaddr``` option followed by destination address
- For filtering by source address, use ```-sp``` or ```--srcport``` option followed by source port
- For filtering by source address, use ```-dp``` or ```--dstport``` option followed by destination port

### GUI
Run GUI application as administrator as:
```bash
sudo python3 gsniffler.py
```

### Example usage
- All packets
  ```bash
  sudo python3 sniffler.py
  ```
- Filter only tcp segments
  ```bash
  sudo python3 sniffler.py -p tcp
  ```
- Filter ethernet frame info and tcp segments
  ```bash
  sudo python3 sniffler.py --proto tcp eth
  ```
- Filter TCP segments from port ```443```
  ```bash
  sudo python3 sniffler.py -p tcp --srcport 443
  ```
- Help
  ```bash
  sudo python3 sniffler.py --help
  ```
- GUI
  ```bash
  sudo python3 gsniffler.py
  ```

### Protocols supported
- [x] TCP segments (IPv4) - tcp
- [x] Ethernet frames - eth
- [x] UDP segments (IPv4) - udp
- [ ] ICMP - icmp