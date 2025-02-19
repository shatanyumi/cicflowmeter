# cicflowmeter
This is a C++ version of CICFlowmeter-V4.0 (formerly known as ISCXFlowMeter) - an Ethernet traffic Bi-flow generator and analyzer for anomaly detection.

## Reference

- [cicflowmeter](https://www.unb.ca/cic/research/applications.html): CICFlowMeter is a network traffic flow generator and analyser.

- [CICFlowMeter-V4.0](https://github.com/CanadianInstituteForCybersecurity/CICFlowMeter)

## Dependence

- [cmake](https://cmake.org/): CMake is the de-facto standard for building C++ code.
- [pcap++](https://pcapplusplus.github.io/): A multi-platform C++ library for capturing, parsing and crafting of network packets.

## Build

Use the follow commands and build the project quickly.

```bash
    mkdir build
    cd build
    cmake ..
    make
```

## Usage

```bash
Usage:
  cicflowmeter [commands and flags] ...

Available Commands:
  tcp       Set TCP timeout (default is 600 seconds)
  udp       Set UDP timeout (default is 600 seconds)
  help      Show help information

Flags:
  -h, --help      Show help for a command
  -t, --timeout   Set timeout value (in seconds)

You can chain commands in one call, e.g.
  cicflowmeter tcp -t 30 udp -t 60
Use "cicflowmeter [command] --help" for more information about a command.
```