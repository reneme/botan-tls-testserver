/**
 * OCSP Cache Helper for Botan post-quantum TLS test server
 *
 * (C) 2024 René Fischer, René Meusel
 */

#ifndef OCSP_CACHE_H
#define OCSP_CACHE_H

#include <chrono>
#include <map>
#include <optional>
#include <shared_mutex>
#include <vector>

#include <botan/ocsp.h>
#include <botan/x509cert.h>

/**
 * This class is responsible for fetching and caching OCSP responses to be
 * pinned to the server's certificate.
 *
 * OCSP Responses are pulled from the CA's OCSP server and cached as long as
 * they are valid.
 */
class OCSP_Cache {
   public:
      /**
       * @param cache_duration        The maximum duration an OCSP response is cached.
       * @param ocsp_request_timeout  The timeout for OCSP requests.
       */
      OCSP_Cache(std::chrono::minutes cache_duration, std::chrono::seconds ocsp_request_timeout);

      std::vector<uint8_t> getOCSPResponse(const Botan::X509_Certificate& issuer,
                                           const Botan::X509_Certificate& subject);

   private:
      struct CacheEntry {
            std::vector<uint8_t> ocsp_response;
            std::chrono::system_clock::time_point valid_until;
      };

      std::optional<Botan::OCSP::Response> fetchOCSPResponse(const Botan::X509_Certificate& issuer,
                                                             const Botan::X509_Certificate& subject);
      std::vector<uint8_t> fromCache(const std::string& fingerprint) const;
      std::vector<uint8_t> intoCache(const std::string& fingerprint,
                                     const Botan::X509_Certificate& issuer,
                                     const Botan::X509_Certificate& subject,
                                     const Botan::OCSP::Response& response);

   private:
      mutable std::shared_mutex m_mutex;
      std::map<std::string, CacheEntry> m_cache;

      std::chrono::minutes m_cache_duration;
      std::chrono::seconds m_ocsp_request_timeout;
};

#endif