#include "net/tools/quic/quic_inverse_multiplexing_client.h"

#include <thread>
#include <utility>

#include "base/at_exit.h"
#include "base/bind.h"
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

using std::condition_variable;
using std::mutex;
using std::string;
using std::thread;
using std::unique_lock;
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

void QuicInverseMultiplexingClient::DestructClient(int i) {
  if (clients_status_[i] == READY_TO_INITIALIZE) {
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
    unique_lock<mutex> lck(*mutexes_[i]);
    clients_status_[i] = READY_TO_DESTRUCT;
    condition_variables_[i]->notify_one();
    LOG(ERROR) << "Set thread " << i << " READY_TO_DESTRUCT.";
  }
  // Waits until all the tasks finished.
  for (int i = 0; i < int(clients_.size()); i++) {
    threads_[i]->join();
  }
}

void QuicInverseMultiplexingClient::AddServerAddresses(
                                    std::vector<IPEndPoint> server_addresses) {
  server_addresses_.insert(server_addresses_.end(), server_addresses.begin(),
                           server_addresses.end());
}

void QuicInverseMultiplexingClient::RunSimpleClient(int i) {
  base::MessageLoopForIO message_loop;
  CreateAndInitializeClient(i, server_addresses_[i]);
  // Blocks the client thread until Connect is called from main thread.
  unique_lock<mutex> lck(*mutexes_[i]);
  while (clients_status_[i] < READY_TO_CONNECT) {
    condition_variables_[i]->wait(lck);
  }
  lck.unlock();
  SetMaxLengthAndConnect(i, initial_max_packet_length());
  // Blocks the client thread until SendRequestAndWaitForResponse
  // is called from main thread.
  lck.lock();
  while (clients_status_[i] < READY_TO_SEND_REQUEST) {
    condition_variables_[i]->wait(lck);
  }
  lck.unlock();
  SendRequestAndWriteResponse(i, request_headers_, request_body_, request_fin_);
  // Signals main thread that the response is ready.
  unique_lock<mutex> response_lock(response_mutex_);
  num_response_ready_ ++;
  if (num_response_ready_ == int(clients_.size())) {
    response_cv_.notify_one();
  }
  response_lock.unlock();
  // Blocks the client thread until destructor is invoked from main thread.
  lck.lock();
  while (clients_status_[i] < READY_TO_DESTRUCT) {
    condition_variables_[i]->wait(lck);
  }
  lck.unlock();
  DestructClient(i);
}

void QuicInverseMultiplexingClient::CreateAndInitializeClient(
                                              int i, IPEndPoint server_address) {
  LOG(ERROR) << "Thread " << i << " : CreateAndInitializeClient.";
  cert_verifiers_[i] = CertVerifier::CreateDefault();
  unique_ptr<ProofVerifier> verifier;
  if (proof_verifier() == nullptr) {
    verifier = MakeUnique<FakeProofVerifier>();
  } else {
/*    verifier = MakeUnique<ProofVerifierChromium>(
              cert_verifiers_[i].get(), new CTPolicyEnforcer(),
              new TransportSecurityState, new MultiLogCTVerifier());
*/    verifier = MakeUnique<FakeProofVerifier>();

  }
  clients_[i].reset(new QuicSimpleClient(server_address, server_id(),
                                         supported_versions(),
                                         std::move(verifier)));
  clients_[i]->Initialize();
  LOG(ERROR) << "Thread " << i << " : Finish CreateAndInitializeClient.";
}

bool QuicInverseMultiplexingClient::Initialize() {
  // Initializes client vector and thread vector.
  // Starts client threads.
  for (int i = 0; i < int(server_addresses_.size()); i++) {
    clients_.push_back(std::unique_ptr<QuicSimpleClient>(nullptr));
    clients_status_.push_back(READY_TO_INITIALIZE);
    cert_verifiers_.push_back(nullptr);
    mutexes_.push_back(MakeUnique<mutex>());
    condition_variables_.push_back(MakeUnique<condition_variable>());
    threads_.push_back(MakeUnique<thread>([=] { RunSimpleClient(i); }));
  }
  return true;
}

void QuicInverseMultiplexingClient::SetMaxLengthAndConnect(
                                   int i, QuicByteCount init_max_packet_length) {
  LOG(ERROR) << "Thread " << i << " : SetMaxLengthAndConnect.";
  // set_initial_max_packet_length need to be called before Connect().
  clients_[i]->set_initial_max_packet_length(init_max_packet_length);
  if (!clients_[i]->Connect()) {
    LOG(ERROR) << "Fail to connect to "
               << clients_[i]->server_address().ToString();
  }
  LOG(ERROR) << "Thread " << i << " : Connected.";
}

bool QuicInverseMultiplexingClient::Connect() {
  for (int i = 0; i < int(clients_.size()); i++) {
    unique_lock<mutex> lck(*mutexes_[i]);
    clients_status_[i] = READY_TO_CONNECT;
    condition_variables_[i]->notify_one();
    LOG(ERROR) << "Set thread " << i << " READY_TO_CONNECT.";
  }
  return true;
}

void QuicInverseMultiplexingClient::SendRequestAndWriteResponse(
    int i, const SpdyHeaderBlock& headers, base::StringPiece body, bool fin) {
  LOG(ERROR) << "Thread " << i << " : SendRequestAndWriteResponse.";
  clients_[i]->set_store_response(store_response_);
  clients_[i].get()->SendRequestAndWaitForResponse(headers, body, fin);
  LOG(ERROR) << "Thread " << i << " : Response received.";
  // TODO: Parses sequence number from response.
  // Assumes sequence number is encoded in the first byte of body.
  int seq_num = i;
/*
  int seq_num = clients_[i]->latest_response_body().empty()
          ? i : int(clients_[i]->latest_response_body()[0]);
  // Doublechecks if the sequence number is valid.
  seq_num = (seq_num == 0 || seq_num == 1) ? seq_num : i;
  response_buf_[seq_num] = MakeUnique<string>(
                            clients_[i]->latest_response_body().substr(1));
*/
  LOG(ERROR) << "Length: "
             << clients_[i]->latest_response_body().length();
  response_buf_[seq_num] = MakeUnique<string>(
                            clients_[i]->latest_response_body());
}

void QuicInverseMultiplexingClient::SendRequestAndWaitForResponse(
      SpdyHeaderBlock& headers, base::StringPiece body, bool fin) {
  request_headers_ = std::move(headers);
  request_body_ = body;
  request_fin_ = fin;
  for (int i = 0; i < int(clients_.size()); i++) {
    unique_lock<mutex> lck(*mutexes_[i]);
    clients_status_[i] = READY_TO_SEND_REQUEST;
    condition_variables_[i]->notify_one();
    LOG(ERROR) << "Set thread " << i << " READY_TO_SEND_REQUEST.";
  }
  // Wait for responses from all threads to be ready.
  unique_lock<mutex> response_lock(response_mutex_);
  while (num_response_ready_ < int(clients_.size())) {
    response_cv_.wait(response_lock);
  }
  for(int i = 0; i < int(clients_.size()); i++) {
    latest_response_body_ += *(response_buf_[i]);
  }
  LOG(ERROR) << latest_response_body_.size();
  latest_response_headers_ = clients_.back()->latest_response_headers();
  latest_response_trailers_ = clients_.back()->latest_response_trailers();
  latest_response_code_ = clients_.back()->latest_response_code();
  num_response_ready_ = 0;
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
  return nullptr;
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
