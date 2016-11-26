#include "net/tools/quic/quic_inverse_multiplexing_client.h"

#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
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

void QuicInverseMultiplexingClient::ShutdownClient(int i) {
  if (clients_status_[i] == UNINITIALIZED) {
    LOG(ERROR) << "Attempt to destruct uninitialized client.";
  }
  if (clients_[i]->connected()) {
    clients_[i]->session()->connection()->CloseConnection(
        QUIC_PEER_GOING_AWAY, "Shutting down",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    // Destories unique_ptr to client and cert_verifier in the same thread
    // that they are created.
    clients_[i].reset(nullptr);
    cert_verifiers_[i].reset(nullptr);
  }
}

QuicInverseMultiplexingClient::~QuicInverseMultiplexingClient() {
  for (int i = 0; i < int(clients_.size()); i++) {
    threads_[i]->task_runner()->PostTask(
        FROM_HERE,
        base::Bind(&QuicInverseMultiplexingClient::ShutdownClient,
                   base::Unretained(this), i));
  }
  // Waits till all the tasks finished.
  for (int i = 0; i < int(clients_.size()); i++) {
    threads_[i]->FlushForTesting();
  }
}

void QuicInverseMultiplexingClient::AddServerAddresses(
                                    std::vector<IPEndPoint> server_addresses) {
  server_addresses_.insert(server_addresses_.end(), server_addresses.begin(),
                           server_addresses.end());
}

void QuicInverseMultiplexingClient::CreateAndInitializeClient(
                                              int i, IPEndPoint server_address) {
  LOG(ERROR) << "Thread " << i << " : CreateAndInitializeClient.";
  cert_verifiers_[i] = CertVerifier::CreateDefault();
  unique_ptr<ProofVerifier> verifier;
  if (proof_verifier() == nullptr) {
    verifier = MakeUnique<FakeProofVerifier>();
  } else {
/*
    verifier = MakeUnique<ProofVerifierChromium>(
              cert_verifiers_[i].get(), new CTPolicyEnforcer(),
              new TransportSecurityState, new MultiLogCTVerifier());
*/
    verifier = MakeUnique<FakeProofVerifier>();

  }
  clients_[i].reset(new QuicSimpleClient(server_address, server_id(),
                                         supported_versions(),
                                         std::move(verifier)));
  clients_[i]->Initialize();
  clients_status_[i] = INITIALIZED;
}

bool QuicInverseMultiplexingClient::Initialize() {
  // Initializes client vector and thread vector.
  for (auto& server_address : server_addresses_) {
    clients_.push_back(std::unique_ptr<QuicSimpleClient>(nullptr));
    threads_.push_back(MakeUnique<base::Thread>(server_address.ToString()));
    clients_status_.push_back(UNINITIALIZED);
    cert_verifiers_.push_back(nullptr);
  }
  // Starts thread and call PostTask with Initialize
  for (int i = 0; i < int(server_addresses_.size()); i++) {
    // Creates a ProofVerifier for each SimpleClient.

    base::Thread::Options options(base::MessageLoop::TYPE_IO, 0);
    threads_[i]->StartWithOptions(options);
    threads_[i]->task_runner()->PostTask(
        FROM_HERE,
        base::Bind(&QuicInverseMultiplexingClient::CreateAndInitializeClient,
                   base::Unretained(this), i, server_addresses_[i]));
  }
  return true; // TODO: return the actual status.
}

void QuicInverseMultiplexingClient::SetMaxLengthAndConnect(
                                   int i, QuicByteCount init_max_packet_length) {
  LOG(ERROR) << "Thread " << i << " : SetMaxLengthAndConnect.";
  // Blocks until client is initialized.
  while (clients_status_[i] != INITIALIZED) {
    LOG(ERROR) << "Client has not been initialized yet.";
  } 
  // set_initial_max_packet_length need to be called before Connect().
  clients_[i]->set_initial_max_packet_length(init_max_packet_length);
  if (!clients_[i]->Connect()) {
    LOG(ERROR) << "Fail to connect to "
               << clients_[i]->server_address().ToString();
  }
  clients_status_[i] = CONNECTED;
  LOG(ERROR) << "Thread " << i << " : Connected.";
}

bool QuicInverseMultiplexingClient::Connect() {
  for (int i = 0; i < int(clients_.size()); i++) {
    threads_[i]->task_runner()->PostTask(
        FROM_HERE,
        base::Bind(&QuicInverseMultiplexingClient::SetMaxLengthAndConnect,
                   base::Unretained(this), i, initial_max_packet_length()));
  }
  return true; // TODO: return the actual status.
}   

void QuicInverseMultiplexingClient::SendRequestAndWriteResponse(
    int i, const SpdyHeaderBlock& headers, base::StringPiece body, bool fin) {
  LOG(ERROR) << "Thread " << i << " : SendRequestAndWriteResponse.";
  // Blocks untill client is connected.
  while (clients_status_[i] != CONNECTED) {
    LOG(ERROR) << "Client has not been connected yet.";
  }
  clients_[i]->set_store_response(store_response_);
  clients_[i].get()->SendRequestAndWaitForResponse(headers, body, fin);
  clients_status_[i] = REQUEST_SENT;
  LOG(ERROR) << "Request Sent.";
  // TODO: write response somewhere.
}

void QuicInverseMultiplexingClient::SendRequestAndWaitForResponse(
      const SpdyHeaderBlock& headers, base::StringPiece body, bool fin) {
  for (int i = 0; i < int(clients_.size()); i++) {
    threads_[i]->task_runner()->PostTask(
        FROM_HERE,
        base::Bind(&QuicInverseMultiplexingClient::SendRequestAndWriteResponse,
                   base::Unretained(this), i, base::ConstRef(headers), body,
                   fin));
  }
  for (int i = 0; i < int(clients_.size()); i++) {
    threads_[i]->FlushForTesting();
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
