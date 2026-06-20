cmake_minimum_required(VERSION 3.20)
project(chat VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/utf-8)
endif()

# libdatachannel is still used for WebSocket/WebSocketServer. SecureChat no
# longer creates WebRTC PeerConnection/DataChannel transports.
find_package(LibDataChannel CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(unofficial-argon2 CONFIG REQUIRED)
find_package(unofficial-sqlite3 CONFIG REQUIRED)

add_library(core STATIC
    src/attachment_transfer.cpp
    src/auth_service.cpp
    src/console_utils.cpp
    src/cert_generation.cpp
    src/cert_utils.cpp
    src/pki_application.cpp
    src/host_session_core.cpp
    src/client_session_core.cpp
    src/room_registry.cpp
    src/secure_relay.cpp
    src/server_state_store.cpp
    src/signaling_server.cpp
    src/websocket_config.cpp
)
set_target_properties(core PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(core PUBLIC
    LibDataChannel::LibDataChannel
    OpenSSL::SSL OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    unofficial::argon2::libargon2
    unofficial::sqlite3::sqlite3
)
target_include_directories(core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
if(WIN32)
    target_link_libraries(core PUBLIC iphlpapi ws2_32)
endif()

add_library(native SHARED
    src/native_api.cpp
)
target_link_libraries(native PRIVATE core)
if(WIN32)
    target_link_libraries(native PRIVATE iphlpapi ws2_32)
endif()
target_include_directories(native PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(host src/host_cli.cpp)
target_link_libraries(host PRIVATE
    core
)
if(WIN32)
    target_link_libraries(host PRIVATE iphlpapi ws2_32 shell32)
endif()
target_include_directories(host PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(server src/server_cli.cpp)
target_link_libraries(server PRIVATE
    core
)
if(WIN32)
    target_link_libraries(server PRIVATE shell32)
endif()
target_include_directories(server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(client src/client_cli.cpp)
target_link_libraries(client PRIVATE
    core
)
if(WIN32)
    target_link_libraries(client PRIVATE shell32)
endif()
target_include_directories(client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(cert src/cert_cli.cpp)
target_link_libraries(cert PRIVATE
    core
)
if(WIN32)
    target_link_libraries(cert PRIVATE shell32)
endif()
target_include_directories(cert PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
