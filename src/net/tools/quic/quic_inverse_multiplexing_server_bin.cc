// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A binary wrapper for QuicServer.  It listens forever on --port
// (default 6121) until it's killed or ctrl-cd to death.

#include <iostream>
#include <cstdlib>
#include <thread>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/chromium/crypto/proof_source_chromium.h"
#include "net/quic/core/quic_protocol.h"
#include "net/tools/quic/quic_in_memory_cache.h"
#include "net/tools/quic/quic_inverse_multiplexing_server.h"

// The port the quic server will listen on.
int32_t FLAGS_port = 6121;
int32_t FLAGS_port2 = 6122;

std::unique_ptr<net::ProofSource> CreateProofSource(
    const base::FilePath& cert_path,
    const base::FilePath& key_path) {
  std::unique_ptr<net::ProofSourceChromium> proof_source(
      new net::ProofSourceChromium());
  CHECK(proof_source->Initialize(cert_path, key_path, base::FilePath()));
  return std::move(proof_source);
}

// Starts a server with given port and runs the message loop.
void StartServer(int32_t port, const base::CommandLine* line) {
  net::IPAddress ip = net::IPAddress::IPv6AllZeros();

  net::QuicConfig config;
  net::QuicInverseMultiplexingServer server(
      CreateProofSource(line->GetSwitchValuePath("certificate_file"),
                        line->GetSwitchValuePath("key_file")),
      config, net::QuicCryptoServerConfig::ConfigOptions(),
      net::AllSupportedVersions());
  server.SetStrikeRegisterNoStartupPeriod();

  int rc = server.Listen(net::IPEndPoint(ip, port));
  if (rc < 0) {
    exit(1);
  }

  base::RunLoop().Run();
}

void StartPort2Thread(int32_t port, const base::CommandLine* line) {
  base::MessageLoopForIO message_loop;
  StartServer(port, line);
}

int main(int argc, char* argv[]) {
  base::AtExitManager exit_manager;
  base::MessageLoopForIO message_loop;

  base::CommandLine::Init(argc, argv);
  base::CommandLine* line = base::CommandLine::ForCurrentProcess();

  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  CHECK(logging::InitLogging(settings));

  if (line->HasSwitch("h") || line->HasSwitch("help")) {
    const char* help_str =
        "Usage: quic_server [options]\n"
        "\n"
        "Options:\n"
        "-h, --help                  show this help message and exit\n"
        "--port=<port>               specify the port to listen on\n"
        "--port2=<port>              specify the port to listen on\n"
        "--quic_in_memory_cache_dir  directory containing response data\n"
        "                            to load\n"
        "--certificate_file=<file>   path to the certificate chain\n"
        "--key_file=<file>           path to the pkcs8 private key\n";
    std::cout << help_str;
    exit(0);
  }

  if (line->HasSwitch("quic_in_memory_cache_dir")) {
    net::QuicInMemoryCache::GetInstance()->InitializeFromDirectory(
        line->GetSwitchValueASCII("quic_in_memory_cache_dir"));
  }

  if (line->HasSwitch("port")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("port"), &FLAGS_port)) {
      LOG(ERROR) << "--port must be an integer\n";
      return 1;
    }
  }

  if (line->HasSwitch("port2")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("port2"), &FLAGS_port2)) {
      LOG(ERROR) << "--port2 must be an integer\n";
      return 1;
    }
  }

  if (!line->HasSwitch("certificate_file")) {
    LOG(ERROR) << "missing --certificate_file";
    return 1;
  }

  if (!line->HasSwitch("key_file")) {
    LOG(ERROR) << "missing --key_file";
    return 1;
  }

  std::thread port2_thread(StartPort2Thread, FLAGS_port2, line);

  // Should only return when this thread's message loop quits.
  StartServer(FLAGS_port, line);

  return 0;
}
