// An inverse multiplexing quic client.
#ifndef NET_TOOLS_QUIC_QUIC_INVERSE_MULTIPLEXING_CLIENT_H_
#define NET_TOOLS_QUIC_QUIC_INVERSE_MULTIPLEXING_CLIENT_H_

#include <stddef.h>

#include <memory>
#include <string>

#include "base/command_line.h"
#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "base/threading/thread.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/http/http_response_headers.h"
#include "net/log/net_log.h"
#include "net/quic/chromium/quic_chromium_packet_reader.h"
#include "net/quic/core/quic_config.h"
#include "net/quic/core/quic_spdy_stream.h"
#include "net/tools/quic/quic_client_base.h"
#include "net/tools/quic/quic_simple_client.h"

#include "net/cert/cert_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/http/transport_security_state.h"
#include "net/quic/chromium/crypto/proof_verifier_chromium.h"


namespace net {

class QuicInverseMultiplexingClient : public QuicClientBase {
 public:
  class FakeProofVerifier : public ProofVerifier {
   public:
    QuicAsyncStatus VerifyProof(
        const std::string& hostname,
        const uint16_t port,
        const std::string& server_config,
        QuicVersion quic_version,
        base::StringPiece chlo_hash,
        const std::vector<std::string>& certs,
        const std::string& cert_sct,
        const std::string& signature,
        const ProofVerifyContext* context,
        std::string* error_details,
        std::unique_ptr<ProofVerifyDetails>* details,
        std::unique_ptr<ProofVerifierCallback> callback) override;
  
    QuicAsyncStatus VerifyCertChain(
        const std::string& hostname,
        const std::vector<std::string>& certs,
        const ProofVerifyContext* verify_context,
        std::string* error_details,
        std::unique_ptr<ProofVerifyDetails>* verify_details,
        std::unique_ptr<ProofVerifierCallback> callback) override;
  };

  QuicInverseMultiplexingClient(IPEndPoint server_address,
                                const QuicServerId& server_id,
                                const QuicVersionVector& supported_versions,
                                std::unique_ptr<ProofVerifier> proof_verifier);
  QuicInverseMultiplexingClient(IPEndPoint server_address,
                                const QuicServerId& server_id,
                                const QuicVersionVector& supported_versions,
                                const QuicConfig& config,
                                std::unique_ptr<ProofVerifier> proof_verifier);

  ~QuicInverseMultiplexingClient() override;

  // Adds server addresses for multiple QUIC connections.
  // This should be called before Initialize().
  void AddServerAddresses(std::vector<IPEndPoint> server_addresses);
  
  // Initialize one or multiple QUIC simple clients with each connects to a
  // given server_address. 
  bool Initialize() override;

  // TODO: Make the base class method virtual?
  bool Connect();

  void SendRequestAndWaitForResponse(const SpdyHeaderBlock& headers,
                                     base::StringPiece body,
                                     bool fin);

  // This is a stub. It is only called in MigrateSocket().
  IPEndPoint GetLatestClientAddress() const override;

  // TODO: session()->error(). Session error handling.
  // Get response.
  const std::string& latest_response_headers() const { 
    return latest_response_headers_; }
  const std::string& latest_response_body() const { 
    return latest_response_body_; }
  const std::string& latest_response_trailers() const { 
    return latest_response_trailers_; }
  size_t latest_response_code() const { 
    return latest_response_code_; }

 protected:
  // This is a stub.
  QuicPacketWriter* CreateQuicPacketWriter() override;
  // This is a stub.
  void RunEventLoop() override;
  // This is a stub.
  bool CreateUDPSocketAndBind(IPEndPoint server_address,
                              IPAddress bind_to_address,
                              int bind_to_port) override;
  // This is a stub.
  void CleanUpAllUDPSockets() override;

 private:
  QuicChromiumConnectionHelper* CreateQuicConnectionHelper();
  QuicChromiumAlarmFactory* CreateQuicAlarmFactory();

  // Helper function executed by each thread.
  void CreateAndInitializeClient(int i, IPEndPoint server_address);
  void SetMaxLengthAndConnect(int i, QuicByteCount init_max_packet_length);
  void SendRequestAndWriteResponse(int i,
                                   const SpdyHeaderBlock& headers,
                                   base::StringPiece body,
                                   bool fin);
  void ShutdownClient(int i);

  // Flag for storing response.
  bool store_response_ = true;

  // TODO: Remove this clock.
  QuicClock clock_;
  
  // Server addresses.
  std::vector<IPEndPoint> server_addresses_;

  // Mutiple QuicSimpleClient.
  std::vector<std::unique_ptr<QuicSimpleClient>> clients_;

  // Client Threads. The client must be initialized and called from same thread.
  std::vector<std::unique_ptr<base::Thread>> threads_;

  // Certificate verifiers.
  std::vector<std::unique_ptr<CertVerifier>> cert_verifiers_;

  // Simple client status.
  enum SimpleClientStatus {
    UNINITIALIZED = 0,
    INITIALIZED = 1, 
    CONNECTED = 2, 
    REQUEST_SENT = 3,
  };
  std::vector<SimpleClientStatus> clients_status_;

  // Response.
  std::string latest_response_headers_ = "";
  std::string latest_response_body_ = "";
  std::string latest_response_trailers_ = "";
  size_t latest_response_code_ = 0;

  DISALLOW_COPY_AND_ASSIGN(QuicInverseMultiplexingClient);
};

}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_INVERSE_MULTIPLEXING_CLIENT_H_

