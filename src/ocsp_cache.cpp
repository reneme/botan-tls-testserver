/**
 * OCSP Cache Helper for Botan post-quantum TLS test server
 *
 * (C) 2024 René Fischer, René Meusel
 */

#include "ocsp_cache.h"

#include <boost/asio.hpp>
#include <boost/beast.hpp>

#include <iostream>
#include <mutex>

namespace {

struct URL {
      std::string protocol;
      std::string host;
      std::optional<std::string> port;
      std::string target;
};

std::optional<URL> parse_url(const std::string& urlstr) {
   const auto protocol_host_sep = urlstr.find("://");
   if(protocol_host_sep == std::string::npos) {
      return {};
   }

   const auto host_target_sep = urlstr.find('/', protocol_host_sep + 3);

   URL url;

   if(host_target_sep == std::string::npos) {
      url.host = urlstr.substr(protocol_host_sep + 3, std::string::npos);
      url.target = "/";
   } else {
      url.host = urlstr.substr(protocol_host_sep + 3, host_target_sep - protocol_host_sep - 3);
      url.target = urlstr.substr(host_target_sep, std::string::npos);
   }

   const auto port_sep = url.host.find(':');
   if(port_sep == std::string::npos) {
      url.protocol = "http";
      // hostname not modified
   } else {
      url.port = url.host.substr(port_sep + 1, std::string::npos);
      url.host = url.host.substr(0, port_sep);
   }

   return url;
}

}  // namespace

OCSP_Cache::OCSP_Cache(std::chrono::minutes cache_duration, std::chrono::seconds ocsp_request_timeout) :
      m_cache_duration(cache_duration), m_ocsp_request_timeout(ocsp_request_timeout) {}

std::vector<uint8_t> OCSP_Cache::getOCSPResponse(const Botan::X509_Certificate& issuer,
                                                 const Botan::X509_Certificate& subject) {
   const auto fingerprint = subject.fingerprint("SHA-256");
   if(auto cached_ocsp_response = fromCache(fingerprint); !cached_ocsp_response.empty()) {
      return cached_ocsp_response;
   }

   const auto response_from_server = fetchOCSPResponse(issuer, subject);
   if(!response_from_server.has_value() ||
      response_from_server->status() != Botan::OCSP::Response_Status_Code::Successful ||
      response_from_server->status_for(issuer, subject, std::chrono::system_clock::now()) !=
         Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD) {
      return {};
   }

   // We do not explicitly check the signature of the OCSP response. Clients
   // will do that and reject if the response was counterfeit for some reason.

   return intoCache(fingerprint, issuer, subject, response_from_server.value());
}

std::optional<Botan::OCSP::Response> OCSP_Cache::fetchOCSPResponse(const Botan::X509_Certificate& issuer,
                                                                   const Botan::X509_Certificate& subject) {
   const auto responder = subject.ocsp_responder();
   std::cout << "going to fetch OCSP response from " << responder << "\n";

   if(responder.empty()) {
      return {};
   }

   const auto url = parse_url(responder);
   if(!url.has_value()) {
      return {};
   }

   const Botan::OCSP::Request req(issuer, subject);

   namespace http = boost::beast::http;
   namespace asio = boost::asio;
   using tcp = boost::asio::ip::tcp;

   // Create an io_context
   asio::io_context ioc;

   // Lookup the domain name
   tcp::resolver resolver(ioc);
   const auto results = resolver.resolve(url->host, url->port.value_or(url->protocol == "http" ? "80" : "443"));

   // Create a TCP stream
   boost::beast::tcp_stream socket(ioc);
   socket.expires_after(m_ocsp_request_timeout);
   socket.connect(results);

   // Create an HTTP request
   http::request<http::vector_body<uint8_t>> http_request(http::verb::post, url->target, 10);
   http_request.set(http::field::host, url->host);
   http_request.set(http::field::user_agent, "Botan OCSP Client");
   http_request.set(http::field::content_type, "application/ocsp-request");
   http_request.set(http::field::accept, "application/ocsp-response");
   http_request.body() = req.BER_encode();
   http_request.prepare_payload();

   // Send the HTTP request
   http::write(socket, http_request);

   // Receive the HTTP response
   boost::beast::flat_buffer buffer;
   http::response<http::vector_body<uint8_t>> response;
   http::read(socket, buffer, response);

   // Check if the response is successful
   if(response.result() != http::status::ok) {
      return {};
   }

   // Process the response and return the OCSP response
   return Botan::OCSP::Response(response.body());
}

std::vector<uint8_t> OCSP_Cache::fromCache(const std::string& fingerprint) const {
   std::shared_lock lock(m_mutex);

   const auto& entry = m_cache.find(fingerprint);
   if(entry == m_cache.end() || entry->second.valid_until < std::chrono::system_clock::now()) {
      // We don't evict the entry here, as we don't want to obtain a write lock here
      return {};
   }

   return entry->second.ocsp_response;
}

std::vector<uint8_t> OCSP_Cache::intoCache(const std::string& fingerprint,
                                           const Botan::X509_Certificate& issuer,
                                           const Botan::X509_Certificate& subject,
                                           const Botan::OCSP::Response& response) {
   const auto ref_time = std::chrono::system_clock::now();

   // Botan does not offer an API to get the OCSP response's validity period.
   // Also, OCSP responses don't always have a 'next_update` field. We have to
   // (roughly) guess the validity period via exponential backoff.
   auto cache_duration = m_cache_duration;
   while(cache_duration != decltype(cache_duration)::zero() &&
         response.status_for(issuer, subject, ref_time + cache_duration) ==
            Botan::Certificate_Status_Code::OCSP_NOT_YET_VALID) {
      cache_duration /= 2;
   }

   std::cout << "caching OCSP response (" << cache_duration.count() << "min) for " << fingerprint << "\n";

   return [&] {
      std::unique_lock lock(m_mutex);
      auto& new_entry = m_cache[fingerprint];
      new_entry = CacheEntry{.ocsp_response = response.raw_bits(), .valid_until = ref_time + cache_duration};
      return new_entry.ocsp_response;
   }();
}
