/**
 * Botan post-quantum TLS test server
 *
 * (C) 2023 René Fischer, René Meusel
 *
 * This implementation is roughly based on this BSL-licensed boost beast example
 * by Klemens D. Morgenstern:
 *   www.boost.org/doc/libs/1_83_0/libs/beast/example/http/server/awaitable/http_server_awaitable.cpp
 */

#include <chrono>
#include <concepts>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/http.hpp>
#include <boost/program_options.hpp>

#include <botan/asio_stream.h>
#include <botan/auto_rng.h>
#include <botan/pkcs8.h>
#include <botan/tls_session_manager_memory.h>
#include <botan/version.h>

#include "ocsp_cache.h"

namespace {

namespace beast = boost::beast;    // from <boost/beast.hpp>
namespace http = beast::http;      // from <boost/beast/http.hpp>
namespace net = boost::asio;       // from <boost/asio.hpp>
using tcp = boost::asio::ip::tcp;  // from <boost/asio/ip/tcp.hpp>

using tcp_stream = typename beast::tcp_stream::rebind_executor<
   net::use_awaitable_t<>::executor_with_default<net::any_io_executor>>::other;

class Basic_Credentials_Manager final : public Botan::Credentials_Manager {
   public:
      Basic_Credentials_Manager(const std::string& server_crt, const std::string& server_key) {
         Certificate_Info cert;

         Botan::DataSource_Stream key_in(server_key);
         cert.key = Botan::PKCS8::load_key(key_in);

         Botan::DataSource_Stream in(server_crt);
         while(!in.end_of_data()) {
            try {
               cert.certs.push_back(Botan::X509_Certificate(in));
            } catch(std::exception&) {}
         }

         m_creds.push_back(cert);
      }

      std::vector<Botan::X509_Certificate> find_cert_chain(
         const std::vector<std::string>& algos,
         const std::vector<Botan::AlgorithmIdentifier>& cert_signature_schemes,
         const std::vector<Botan::X509_DN>& acceptable_cas,
         const std::string& type,
         const std::string& hostname) override {
         BOTAN_UNUSED(cert_signature_schemes);

         const auto cred = std::ranges::find_if(m_creds, [&](const auto& cred) {
            return std::ranges::any_of(algos, [&](const auto& algo) { return algo == cred.key->algo_name(); }) &&
                   (hostname.empty() || cred.certs.front().matches_dns_name(hostname));
         });

         return (cred != m_creds.end()) ? cred->certs : std::vector<Botan::X509_Certificate>{};
      }

      std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate& cert,
                                                          const std::string& /*type*/,
                                                          const std::string& /*context*/) override {
         const auto cred = std::ranges::find_if(m_creds, [&](const auto& cred) { return cred.certs.front() == cert; });
         return (cred != m_creds.end()) ? cred->key : nullptr;
      }

   private:
      struct Certificate_Info {
            std::vector<Botan::X509_Certificate> certs;
            std::shared_ptr<Botan::Private_Key> key;
      };

      std::vector<Certificate_Info> m_creds;
};

class TlsHttpCallbacks final : public Botan::TLS::StreamCallbacks {
   public:
      TlsHttpCallbacks(std::shared_ptr<OCSP_Cache> ocsp_cache) : m_ocsp_cache(std::move(ocsp_cache)) {}

      Botan::KEM_Encapsulation tls_kem_encapsulate(Botan::TLS::Group_Params group,
                                                   const std::vector<uint8_t>& encoded_public_key,
                                                   Botan::RandomNumberGenerator& rng,
                                                   const Botan::TLS::Policy& policy) override {
         m_group = group;
         return Botan::TLS::StreamCallbacks::tls_kem_encapsulate(group, encoded_public_key, rng, policy);
      }

      std::vector<uint8_t> tls_provide_cert_status(const std::vector<Botan::X509_Certificate>& chain,
                                                   const Botan::TLS::Certificate_Status_Request& csr) override {
         if(chain.size() < 2) {
            return {};
         }

         return m_ocsp_cache->getOCSPResponse(chain[1], chain[0]);
      }

      std::string collect_connection_details_as_json() const {
         std::stringstream ss;
         ss << "{"
            << "\"kex_algo\": \"" << m_group.to_string().value_or("unknown") << "\","
            << "\"is_quantum_safe\": " << (m_group.is_post_quantum() ? "true" : "false") << ","
            << "\"wire_code\": \"0x" << std::hex << std::setw(4) << std::setfill('0') << m_group.wire_code() << "\""
            << "}";
         return ss.str();
      }

   private:
      Botan::TLS::Group_Params m_group = Botan::TLS::Group_Params::NONE;
      std::shared_ptr<OCSP_Cache> m_ocsp_cache;
};

inline std::shared_ptr<Botan::TLS::Policy> load_tls_policy(const std::string& policy_type) {
   if(policy_type == "default" || policy_type.empty()) {
      return std::make_shared<Botan::TLS::Policy>();
   }

   // if something we don't recognize, assume it's a file
   std::ifstream policy_stream(policy_type);
   if(!policy_stream.good()) {
      throw std::runtime_error("Unknown TLS policy: not a file or known short name");
   }

   return std::make_shared<Botan::TLS::Text_Policy>(policy_stream);
}

auto make_final_completion_handler(const std::string& context) {
   return [=](std::exception_ptr e) {
      if(e) {
         try {
            std::rethrow_exception(std::move(e));
         } catch(const std::exception& ex) {
            const auto now = std::chrono::system_clock::now();
            const std::time_t t_c = std::chrono::system_clock::to_time_t(now);
            std::cerr << std::ctime(&t_c) << " " << context << ": " << ex.what() << std::endl;
         }
      }
   };
}

beast::string_view mime_type(beast::string_view path) {
   using beast::iequals;
   const auto ext = [&path] {
      auto const pos = path.rfind(".");
      if(pos == beast::string_view::npos)
         return beast::string_view{};
      return path.substr(pos);
   }();

   if(iequals(ext, ".htm"))
      return "text/html";
   if(iequals(ext, ".html"))
      return "text/html";
   if(iequals(ext, ".css"))
      return "text/css";
   if(iequals(ext, ".txt"))
      return "text/plain";
   if(iequals(ext, ".js"))
      return "application/javascript";
   if(iequals(ext, ".json"))
      return "application/json";
   if(iequals(ext, ".png"))
      return "image/png";
   if(iequals(ext, ".ico"))
      return "image/png";
   if(iequals(ext, ".jpe"))
      return "image/jpeg";
   if(iequals(ext, ".jpeg"))
      return "image/jpeg";
   if(iequals(ext, ".jpg"))
      return "image/jpeg";
   if(iequals(ext, ".gif"))
      return "image/gif";
   if(iequals(ext, ".ico"))
      return "image/vnd.microsoft.icon";
   if(iequals(ext, ".svg"))
      return "image/svg+xml";
   if(iequals(ext, ".svgz"))
      return "image/svg+xml";

   return "application/text";
}

std::string path_cat(beast::string_view base, beast::string_view path) {
   if(base.empty()) {
      return std::string(path);
   }

   std::string result(base);

   char constexpr path_separator = '/';
   if(result.back() == path_separator) {
      result.resize(result.size() - 1);
   }
   result.append(path.data(), path.size());

   return result;
}

template <class... Ts>
struct overloaded : Ts... {
      using Ts::operator()...;
};

template <class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;

template <class ResponseBody, class Body, class Allocator>
http::message_generator prepare_response(const http::request<Body, http::basic_fields<Allocator>>& req,
                                         http::status status_code,
                                         ResponseBody body,
                                         std::string_view content_type = "text/html") {
   using resp_body_t = std::decay_t<ResponseBody>;

   auto res = [&] {
      if constexpr(std::convertible_to<resp_body_t, std::string>) {
         http::response<http::string_body> r{status_code, req.version()};
         r.body() = std::string(body);
         return r;
      } else if constexpr(std::integral<resp_body_t>) {
         http::response<http::empty_body> r{status_code, req.version()};
         r.content_length(body);
         return r;
      } else if constexpr(std::same_as<http::file_body::value_type, resp_body_t>) {
         return http::response<http::file_body>{
            std::piecewise_construct, std::make_tuple(std::move(body)), std::make_tuple(status_code, req.version())};
      } else {
         static_assert(std::integral<resp_body_t>, "Cannot handle the given response body");
      }
   }();

   res.set(http::field::server, std::string("Botan ") + Botan::short_version_string());
   res.set(http::field::content_type, content_type);
   res.keep_alive(req.keep_alive());

   if constexpr(!std::integral<resp_body_t>) {
      res.prepare_payload();
   }

   return res;
}

// Returns a bad request response
template <class Body, class Allocator>
auto bad_request(const http::request<Body, http::basic_fields<Allocator>>& req, std::string why) {
   return prepare_response(req, http::status::bad_request, std::move(why));
};

// Returns a not found response
template <class Body, class Allocator>
auto not_found(const http::request<Body, http::basic_fields<Allocator>>& req) {
   return prepare_response(req, http::status::not_found, req.target());
};

// Returns a server error response
template <class Body, class Allocator>
auto server_error(const http::request<Body, http::basic_fields<Allocator>>& req, const std::string& what) {
   return prepare_response(req, http::status::internal_server_error, std::string("An error occured: ") + what);
};

// Returns a success response
template <class ResponseBody, class Body, class Allocator>
auto success(const http::request<Body, http::basic_fields<Allocator>>& req,
             ResponseBody&& body,
             std::string_view content_type = "text/html") {
   return prepare_response(req, http::status::ok, std::forward<ResponseBody>(body), content_type);
}

template <class Body, class Allocator>
http::message_generator handle_request(http::request<Body, http::basic_fields<Allocator>>&& req,
                                       beast::string_view doc_root) {
   // Make sure we can handle the method
   if(req.method() != http::verb::get && req.method() != http::verb::head) {
      return bad_request(req, "Unknown HTTP-method");
   }

   // Request path must be absolute and not contain "..".
   if(req.target().empty() || req.target()[0] != '/' || req.target().find("..") != beast::string_view::npos) {
      return bad_request(req, "Illegal request-target");
   }

   // Build the path to the requested file
   std::string path = path_cat(doc_root, req.target());
   if(req.target().back() == '/') {
      path.append("index.html");
   }

   // Attempt to open the file
   beast::error_code ec;
   http::file_body::value_type body;
   body.open(path.c_str(), beast::file_mode::scan, ec);

   // Handle the case where the file doesn't exist
   if(ec == beast::errc::no_such_file_or_directory) {
      return not_found(req);
   }

   // Handle an unknown error
   if(ec) {
      return server_error(req, ec.message());
   }

   if(req.method() == http::verb::head) {
      // Respond to HEAD request
      return success(req, body.size(), mime_type(path));
   } else {
      // Respond to GET request
      return success(req, std::move(body), mime_type(path));
   }
}

template <class Body, class Allocator>
http::message_generator handle_api_request(http::request<Body, http::basic_fields<Allocator>>&& req,
                                           std::shared_ptr<TlsHttpCallbacks> tls_callbacks) {
   // Make sure we can handle the method
   if(req.method() != http::verb::get) {
      return bad_request(req, "Unknown API method");
   }

   if(req.target() == "/api/connection_details") {
      return success(req, tls_callbacks->collect_connection_details_as_json(), "application/json");
   } else {
      return not_found(req);
   }
}

net::awaitable<void> do_session(tcp_stream stream,
                                std::shared_ptr<Botan::TLS::Context> tls_ctx,
                                std::shared_ptr<OCSP_Cache> ocsp_cache,
                                std::string_view document_root) {
   // This buffer is required to persist across reads
   beast::flat_buffer buffer;

   // Set up Botan's TLS stack
   auto callbacks = std::make_shared<TlsHttpCallbacks>(ocsp_cache);
   Botan::TLS::Stream<tcp_stream> tls_stream(std::move(stream), std::move(tls_ctx), callbacks);

   try {
      // Perform a TLS handshake with the peer
      co_await tls_stream.async_handshake(Botan::TLS::Connection_Side::Server);

      while(true) {
         // Set the timeout.
         tls_stream.next_layer().expires_after(std::chrono::seconds(30));

         // Read a request
         http::request<http::string_body> req;
         co_await http::async_read(tls_stream, buffer, req);

         // Handle the request
         auto response = req.target().starts_with("/api") ? handle_api_request(std::move(req), callbacks)
                                                          : handle_request(std::move(req), document_root);

         // Send the response
         const auto keep_alive = response.keep_alive();
         co_await beast::async_write(tls_stream, std::move(response), net::use_awaitable);

         // Determine if we should close the connection
         if(!keep_alive) {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            break;
         }
      }
   } catch(boost::system::system_error& se) {
      if(se.code() != http::error::end_of_stream) {
         throw;
      }
   }

   // Shut down the connection gracefully
   co_await tls_stream.async_shutdown();
   beast::error_code ec;
   tls_stream.next_layer().socket().shutdown(tcp::socket::shutdown_send, ec);

   // At this point the connection is closed gracefully
   // we ignore the error because the client might have
   // dropped the connection already.
}

net::awaitable<void> do_listen(tcp::endpoint endpoint,
                               std::shared_ptr<Botan::TLS::Context> tls_ctx,
                               std::shared_ptr<OCSP_Cache> ocsp_cache,
                               std::string_view document_root) {
   auto acceptor = net::use_awaitable.as_default_on(tcp::acceptor(co_await net::this_coro::executor));
   acceptor.open(endpoint.protocol());
   acceptor.set_option(net::socket_base::reuse_address(true));
   acceptor.bind(endpoint);
   acceptor.listen(net::socket_base::max_listen_connections);

   // If max_clients is zero in the beginning, we'll serve forever
   // otherwise we'll count down and stop eventually.
   while(true) {
      boost::asio::co_spawn(
         acceptor.get_executor(),
         do_session(tcp_stream(co_await acceptor.async_accept()), tls_ctx, ocsp_cache, document_root),
         make_final_completion_handler("Session"));
   }
}

}  // namespace

int main(int argc, char* argv[]) {
   // clang-format off
   boost::program_options::options_description desc("Allowed options");
   desc.add_options()
      ("help", "produce help message")
      ("port", boost::program_options::value<uint16_t>()->required(), "Port to use")
      ("policy", boost::program_options::value<std::string>()->default_value("default"), "Botan policy file (default: Botan's default policy)")
      ("cert", boost::program_options::value<std::string>()->required(), "Path to the server's certificate chain")
      ("key", boost::program_options::value<std::string>()->required(), "Path to the server's certificate private key file")
      ("ocsp-request-timeout", boost::program_options::value<uint64_t>()->default_value(10), "OCSP request timeout in seconds")
      ("ocsp-cache-time", boost::program_options::value<uint64_t>()->default_value(6 * 60), "Cache validity time for OCSP responses in minutes")
      ("document-root", boost::program_options::value<std::string>()->default_value("webroot"), "Path to the server's static documents folder");
   // clang-format on

   boost::program_options::variables_map vm;
   try {
      boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);

      if(vm.count("help") != 0 || argc < 2) {
         std::cerr << "Usage: \n" << desc << std::endl;
         return 0;
      }

      boost::program_options::notify(vm);
   } catch(const std::exception& ex) {
      std::cerr << ex.what() << std::endl;
      return 1;
   }

   try {
      const auto port = vm["port"].as<uint16_t>();
      const auto policy = vm["policy"].as<std::string>();
      const auto certificate = vm["cert"].as<std::string>();
      const auto key = vm["key"].as<std::string>();
      const auto document_root = vm["document-root"].as<std::string>();

      auto creds = std::make_shared<Basic_Credentials_Manager>(certificate, key);
      auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
      auto session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
      auto tls_policy = load_tls_policy(policy);

      const auto num_threads = std::thread::hardware_concurrency();
      net::io_context io{static_cast<int>(num_threads)};
      auto address = net::ip::make_address("0.0.0.0");
      boost::asio::co_spawn(
         io,
         do_listen(tcp::endpoint{address, port},
                   std::make_shared<Botan::TLS::Context>(creds, rng, session_mgr, tls_policy),
                   std::make_shared<OCSP_Cache>(std::chrono::minutes(vm["ocsp-cache-time"].as<uint64_t>()),
                                                std::chrono::seconds(vm["ocsp-request-timeout"].as<uint64_t>())),
                   document_root),
         make_final_completion_handler("Acceptor"));

      std::vector<std::jthread> threads;
      for(size_t i = 2; i <= num_threads; ++i) {
         threads.emplace_back([&io]() { io.run(); });
      }

      io.run();
   } catch(const std::exception& ex) {
      std::cerr << ex.what() << std::endl;
      return 1;
   }

   return 0;
}
