#pragma once

#include <string>

int connect_to_host_port(const std::string& host, int target_port, int timeout_seconds, bool without_tor);
