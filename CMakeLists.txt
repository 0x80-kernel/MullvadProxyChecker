cmake_minimum_required(VERSION 3.10)
project(MullvadProxyChecker VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(mullvad_proxy_checker
  main.cpp
  MullvadProxyChecker.cpp
)

find_package(fmt REQUIRED)
find_package(CURL REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(Threads REQUIRED)

target_link_libraries(mullvad_proxy_checker PRIVATE
  fmt::fmt
  CURL::libcurl
  nlohmann_json::nlohmann_json
  Threads::Threads
)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(mullvad_proxy_checker PRIVATE -Wall -Wextra)
elseif(MSVC)
    target_compile_options(mullvad_proxy_checker PRIVATE /W4)
endif()

install(TARGETS mullvad_proxy_checker
  RUNTIME DESTINATION bin
)
