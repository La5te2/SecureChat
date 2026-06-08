#pragma once

#include <rtc/rtc.hpp>

// Builds the WebRTC ICE configuration shared by Host and Client peers.
rtc::Configuration makePeerConfiguration();
