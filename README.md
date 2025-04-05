# Mullvad Proxy Checker
Scrapes all proxys from [here](https://api.mullvad.net/www/relays/wireguard/ "WIREGUARD API") and pings them with 20 threads, the working ones are saved on proxies.txt.
## Build
``
mkdir build && cd build
cmake ..
make
``
