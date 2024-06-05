# cicflowmeter
This is a C++ version of CICFlowmeter-V4.0 (formerly known as ISCXFlowMeter) - an Ethernet traffic Bi-flow generator and analyzer for anomaly detection.

## reference

- [cicflowmeter python version](https://github.com/hieulw/cicflowmeter)
- [cicflowmeter java version](https://github.com/ahlashkari/CICFlowMeter)

## build

CMake tools, C++ compiler, libpcap-dev and gtest are needed. For example, build the project with ubuntu 23 LTS.

```bash
sudo apt install g++ cmake libpcap-dev
```

Execute the orders at the project root directory.

```bash
mkdir build
cd build
cmake ..
make
ctest
```

More detials can be seen in `CMakeLists.txt`.

## notes

Hope you enjoy this tool. Feel free to pull and issue.(Bugs may exists!)