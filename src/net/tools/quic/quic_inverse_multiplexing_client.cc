#include "net/tools/quic/quic_inverse_multiplexing_client.h"

#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/threading/thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/net_errors.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_info.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_with_source.h"
#include "net/quic/chromium/quic_chromium_alarm_factory.h"
#include "net/quic/chromium/quic_chromium_connection_helper.h"
#include "net/quic/chromium/quic_chromium_packet_reader.h"
#include "net/quic/chromium/quic_chromium_packet_writer.h"
#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_protocol.h"
#include "net/quic/core/quic_server_id.h"
#include "net/quic/core/spdy_utils.h"
#include "net/spdy/spdy_header_block.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/udp/udp_client_socket.h"

using std::string;
using std::unique_ptr;
using std::vector;
using base::MakeUnique;
using base::StringPiece;

namespace net {

QuicInverseMultiplexingClient::QuicInverseMultiplexingClient(
    IPEndPoint server_address,
    const QuicServerId& server_id,
    const QuicVersionVector& supported_versions,
    unique_ptr<ProofVerifier> proof_verifier)
    : QuicInverseMultiplexingClient(server_address,
                                    server_id,
                                    supported_versions,
                                    QuicConfig(),
                                    std::move(proof_verifier)) {}

QuicInverseMultiplexingClient::QuicInverseMultiplexingClient(
    IPEndPoint server_address,
    const QuicServerId& server_id,
    const QuicVersionVector& supported_versions,
    const QuicConfig& config,
    unique_ptr<ProofVerifier> proof_verifier)
    : QuicClientBase(server_id,
                     supported_versions,
                     config,
                     CreateQuicConnectionHelper(),
                     CreateQuicAlarmFactory(),
                     std::move(proof_verifier)) {
  set_server_address(server_address);  // This sets server_address_. Keeps here
                                       // so that other functions won't break.
  server_addresses_.push_back(server_address);
}

QuicInverseMultiplexingClient::~QuicInverseMultiplexingClient() {
  for (auto& client : clients_) {
    if (client->connected()) {
      client->session()->connection()->CloseConnection(
          QUIC_PEER_GOING_AWAY, "Shutting down",
          ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    }
  }
}

void QuicInverseMultiplexingClient::AddServerAddresses(
                                    std::vector<IPEndPoint> server_addresses) {
  server_addresses_.insert(server_addresses_.end(), server_addresses.begin(),
                           server_addresses.end());
}

bool QuicInverseMultiplexingClient::Initialize() {
  bool all_initialized = true;
  for (auto& server_address : server_addresses_) {
    cert_verifiers_.push_back(CertVerifier::CreateDefault());
    unique_ptr<ProofVerifier> verifier;
    if (proof_verifier() == nullptr) {
      verifier = MakeUnique<FakeProofVerifier>();
    } else {
      verifier = MakeUnique<ProofVerifierChromium>(
              cert_verifiers_.back().get(), new CTPolicyEnforcer(),
              new TransportSecurityState, new MultiLogCTVerifier());
    }
    clients_.push_back(MakeUnique<QuicSimpleClient>(server_address, server_id(),
                                                    supported_versions(),
                                                    std::move(verifier)));
    all_initialized &= clients_.back()->Initialize();
  }
  return all_initialized;
}

bool QuicInverseMultiplexingClient::Connect() {
  // set_initial_max_packet_length need to be called before Connect().
  bool is_connected = false;
  for (auto& client : clients_) {
    client->set_initial_max_packet_length(initial_max_packet_length());
    if (client->Connect()) {
      is_connected = true;
    } else {
      LOG(ERROR) << client->server_address().ToString()
                 << " failed to connect.";
    }
  }
  return is_connected;
}

void QuicInverseMultiplexingClient::SendRequestAndWaitForResponse(
      const SpdyHeaderBlock& headers, base::StringPiece body, bool fin) {
  // Sends the same request through all the clients_.
  // TODO: Use a thread for each client.
  vector<unique_ptr<base::Thread>> threads;
  for (auto& client : clients_) {
    client->set_store_response(store_response_);
    client->SendRequest(headers, body, fin);
  }
  for (auto& client : clients_) {
    client->WaitForResponse();
  }
  // TODO: parse the body of each response and buffer it in the right order.
  // TODO: merge two loops together.
  for (auto& client : clients_) {
    latest_response_body_ += client->latest_response_body();
  }
  latest_response_headers_ = clients_.back()->latest_response_headers();
  latest_response_trailers_ = clients_.back()->latest_response_trailers();
  latest_response_code_ = clients_.back()->latest_response_code();
}

QuicAsyncStatus QuicInverseMultiplexingClient::FakeProofVerifier::VerifyProof(
    const string& hostname,
    const uint16_t port,
    const string& server_config,
    QuicVersion quic_version,
    base::StringPiece chlo_hash,
    const vector<std::string>& certs,
    const string& cert_sct,
    const string& signature,
    const ProofVerifyContext* context,
    string* error_details,
    unique_ptr<ProofVerifyDetails>* details,
    unique_ptr<ProofVerifierCallback> callback) {
  return QUIC_SUCCESS;
}

QuicAsyncStatus
QuicInverseMultiplexingClient::FakeProofVerifier::VerifyCertChain(
    const string& hostname,
    const vector<std::string>& certs,
    const ProofVerifyContext* verify_context,
    string* error_details,
    unique_ptr<ProofVerifyDetails>* verify_details,
    unique_ptr<ProofVerifierCallback> callback) {
  return QUIC_SUCCESS;
}


// This is a stub.
QuicChromiumConnectionHelper*
QuicInverseMultiplexingClient::CreateQuicConnectionHelper() {
  return new QuicChromiumConnectionHelper(&clock_, QuicRandom::GetInstance());
}

// This is a stub.
QuicChromiumAlarmFactory*
QuicInverseMultiplexingClient::CreateQuicAlarmFactory() {
  return new QuicChromiumAlarmFactory(base::ThreadTaskRunnerHandle::Get().get(),
                                      &clock_);
}

// This is a stub.
IPEndPoint QuicInverseMultiplexingClient::GetLatestClientAddress() const {
  return clients_.front()->GetLatestClientAddress();
}

// This is a stub.
QuicPacketWriter* QuicInverseMultiplexingClient::CreateQuicPacketWriter() {
  return nullptr;
}

// This is a stub.
void QuicInverseMultiplexingClient::RunEventLoop() {}

// This is a stub.
bool QuicInverseMultiplexingClient::CreateUDPSocketAndBind(
    IPEndPoint server_address, IPAddress bind_to_address, int bind_to_port) {
  return true;
}

// This is a stub.
void QuicInverseMultiplexingClient::CleanUpAllUDPSockets() {}

}  // namespace net
