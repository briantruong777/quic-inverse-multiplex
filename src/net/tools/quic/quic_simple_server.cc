// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_simple_server.h"

#include <string.h>

#include "base/location.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/log/net_log_source.h"
#include "net/quic/core/crypto/crypto_handshake.h"
#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/quic_crypto_stream.h"
#include "net/quic/core/quic_data_reader.h"
#include "net/quic/core/quic_protocol.h"
#include "net/tools/quic/quic_simple_dispatcher.h"
#include "net/tools/quic/quic_simple_per_connection_packet_writer.h"
#include "net/tools/quic/quic_simple_server_packet_writer.h"
#include "net/tools/quic/quic_simple_server_session_helper.h"
#include "net/udp/udp_server_socket.h"

namespace net {

namespace {

const char kSourceAddressTokenSecret[] = "secret";
const size_t kNumSessionsToCreatePerSocketEvent = 16;

// Allocate some extra space so we can send an error if the client goes over
// the limit.
const int kReadBufferSize = 2 * kMaxPacketSize;

}  // namespace

QuicSimpleServer::QuicSimpleServer(
        std::unique_ptr<ProofSource> proof_source, const QuicConfig& config,
        const QuicCryptoServerConfig::ConfigOptions& crypto_config_options,
        const QuicVersionVector& supported_versions)
    : version_manager_(supported_versions),
      helper_{new QuicChromiumConnectionHelper(&clock_,
                                               QuicRandom::GetInstance()),
              new QuicChromiumConnectionHelper(&clock_,
                                               QuicRandom::GetInstance())},
      alarm_factory_{
              new QuicChromiumAlarmFactory(
                      base::ThreadTaskRunnerHandle::Get().get(), &clock_),
              new QuicChromiumAlarmFactory(
                      base::ThreadTaskRunnerHandle::Get().get(), &clock_)},
      config_(config),
      crypto_config_options_(crypto_config_options),
      crypto_config_(kSourceAddressTokenSecret, QuicRandom::GetInstance(),
                     std::move(proof_source)),
      read_pending_{false, false},
      synchronous_read_count_{0, 0},
      read_buffer_{new IOBufferWithSize(kReadBufferSize),
                   new IOBufferWithSize(kReadBufferSize)},
      weak_factory_(this) {
    Initialize();
}

void QuicSimpleServer::Initialize() {
#if MMSG_MORE
  use_recvmmsg_ = true;
#endif

  // If an initial flow control window has not explicitly been set, then use a
  // sensible value for a server: 1 MB for session, 64 KB for each stream.
  const uint32_t kInitialSessionFlowControlWindow = 1 * 1024 * 1024;  // 1 MB
  const uint32_t kInitialStreamFlowControlWindow = 64 * 1024;         // 64 KB
  if (config_.GetInitialStreamFlowControlWindowToSend() ==
      kMinimumFlowControlSendWindow) {
    config_.SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindow);
  }
  if (config_.GetInitialSessionFlowControlWindowToSend() ==
      kMinimumFlowControlSendWindow) {
    config_.SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindow);
  }

  //TODO: Might need to make two of these for each helper_
  std::unique_ptr<CryptoHandshakeMessage> scfg(crypto_config_.AddDefaultConfig(
      helper_[0]->GetRandomGenerator(), helper_[0]->GetClock(),
      crypto_config_options_));
}

QuicSimpleServer::~QuicSimpleServer() {}

int QuicSimpleServer::Listen(const IPEndPoint& address, int udp_socket_idx) {
  std::unique_ptr<UDPServerSocket> socket(
      new UDPServerSocket(&net_log_, NetLogSource()));

  socket->AllowAddressReuse();

  int rc = socket->Listen(address);
  if (rc < 0) {
    LOG(ERROR) << "Listen() failed: " << ErrorToString(rc);
    return rc;
  }

  // These send and receive buffer sizes are sized for a single connection,
  // because the default usage of QuicSimpleServer is as a test server with
  // one or two clients.  Adjust higher for use with many clients.
  rc = socket->SetReceiveBufferSize(
      static_cast<int32_t>(kDefaultSocketReceiveBuffer));
  if (rc < 0) {
    LOG(ERROR) << "SetReceiveBufferSize() failed: " << ErrorToString(rc);
    return rc;
  }

  rc = socket->SetSendBufferSize(20 * kMaxPacketSize);
  if (rc < 0) {
    LOG(ERROR) << "SetSendBufferSize() failed: " << ErrorToString(rc);
    return rc;
  }

  rc = socket->GetLocalAddress(&server_address_[udp_socket_idx]);
  if (rc < 0) {
    LOG(ERROR) << "GetLocalAddress() failed: " << ErrorToString(rc);
    return rc;
  }

  DVLOG(1) << "Listening on " << server_address_[udp_socket_idx].ToString();

  socket_[udp_socket_idx].swap(socket);

  dispatcher_[udp_socket_idx].reset(new QuicSimpleDispatcher(
      config_, &crypto_config_, &version_manager_,
      std::unique_ptr<QuicConnectionHelperInterface>(helper_[udp_socket_idx]),
      std::unique_ptr<QuicCryptoServerStream::Helper>(
          new QuicSimpleServerSessionHelper(QuicRandom::GetInstance())),
      std::unique_ptr<QuicAlarmFactory>(alarm_factory_[udp_socket_idx])));
  QuicSimpleServerPacketWriter* writer =
      new QuicSimpleServerPacketWriter(socket_[udp_socket_idx].get(), dispatcher_[udp_socket_idx].get());
  dispatcher_[udp_socket_idx]->InitializeWithWriter(writer);

  StartReading(udp_socket_idx);

  return OK;
}

void QuicSimpleServer::Shutdown() {
  // Before we shut down the epoll server, give all active sessions a chance to
  // notify clients that they're closing.
  dispatcher_[0]->Shutdown();
  dispatcher_[1]->Shutdown();

  socket_[0]->Close();
  socket_[1]->Close();
  socket_[0].reset();
  socket_[1].reset();
}

void QuicSimpleServer::StartReading(int udp_socket_idx) {
  if (synchronous_read_count_[udp_socket_idx] == 0) {
    // Only process buffered packets once per message loop.
    dispatcher_[udp_socket_idx]->ProcessBufferedChlos(kNumSessionsToCreatePerSocketEvent);
  }

  if (read_pending_[udp_socket_idx]) {
    return;
  }
  read_pending_[udp_socket_idx] = true;

  int result = socket_[udp_socket_idx]->RecvFrom(
      read_buffer_[udp_socket_idx].get(), read_buffer_[udp_socket_idx]->size(), &client_address_[udp_socket_idx],
      base::Bind(&QuicSimpleServer::OnReadComplete, base::Unretained(this), udp_socket_idx));

  if (result == ERR_IO_PENDING) {
    synchronous_read_count_[udp_socket_idx] = 0;
    if (dispatcher_[udp_socket_idx]->HasChlosBuffered()) {
      // No more packets to read, so yield before processing buffered packets.
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE, base::Bind(&QuicSimpleServer::StartReading,
                                weak_factory_.GetWeakPtr(), udp_socket_idx));
    }
    return;
  }

  if (++synchronous_read_count_[udp_socket_idx] > 32) {
    synchronous_read_count_[udp_socket_idx] = 0;
    // Schedule the processing through the message loop to 1) prevent infinite
    // recursion and 2) avoid blocking the thread for too long.
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&QuicSimpleServer::OnReadComplete,
                              weak_factory_.GetWeakPtr(), udp_socket_idx, result));
  } else {
    OnReadComplete(udp_socket_idx, result);
  }
}

void QuicSimpleServer::OnReadComplete(int udp_socket_idx, int result) {
  read_pending_[udp_socket_idx] = false;
  if (result == 0)
    result = ERR_CONNECTION_CLOSED;

  if (result < 0) {
    LOG(ERROR) << "QuicSimpleServer read failed: " << ErrorToString(result);
    Shutdown();
    return;
  }

  QuicReceivedPacket packet(read_buffer_[udp_socket_idx]->data(), result,
                            helper_[udp_socket_idx]->GetClock()->Now(), false);
  dispatcher_[udp_socket_idx]->ProcessPacket(server_address_[udp_socket_idx], client_address_[udp_socket_idx], packet);

  StartReading();
}

}  // namespace net
