# Mullvad Proxy Checker

Scrapes all proxies from the [Mullvad WireGuard API](https://api.mullvad.net/www/relays/wireguard/) and pings them using 20 threads. The working ones are saved to `proxies.txt`.

## Build

To build the project, run the following commands:

```bash
mkdir build
cd build
cmake ..
make
```

## Prerequisites

* A C++ Compiler (like GCC or Clang)
* CMake (version 3.10 or higher)
* Make
