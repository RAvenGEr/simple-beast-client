#ifndef DIGESTAUTHENTICATOR_H
#define DIGESTAUTHENTICATOR_H

#include <random>
#include <boost/utility/string_view.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>
#include <boost/convert.hpp>
#include <boost/convert/strtol.hpp>
#include <openssl/md5.h>
#include <cppcodec/hex_default_lower.hpp>

namespace simple_http {

class digest_authenticator {
public:
  digest_authenticator(boost::string_view www_authenticate, boost::string_view username,
                       boost::string_view password, boost::string_view uri,
                       boost::string_view method, boost::string_view responseBody)
    : m_authenticate{www_authenticate}, m_username{username},
      m_password{password}, m_uri{uri}, m_method{method}, m_body{responseBody}, m_qop{none} {
  }
  bool generateAuthorization() {
    // Nonce and realm are both required for digest athentication.
    if (!findNonce() || !findRealm()) {
      return false;
    }
    findOpaque();
    findQop();
    findAlgorithm();
    m_cnonce = generateNonce();
    m_nonceCount = updateNonceCount();
    MD5_hash ha1;
    calculateHA1(ha1);
    m_ha1 = hex::encode(ha1, sizeof(ha1));
    MD5_hash ha2;
    calculateHA2(ha2);
    m_ha2 = hex::encode(ha2, sizeof(ha2));
    MD5_hash response;
    calculateResponse(response);
    m_response = hex::encode(response, sizeof(response));
    m_authorization = "Digest username=\"";
    m_authorization.append(m_username.to_string());
    m_authorization.append("\", realm=\"");
    m_authorization.append(m_realm.to_string());
    m_authorization.append("\", nonce=\"");
    m_authorization.append(m_nonce.to_string());
    m_authorization.append("\", uri=\"");
    m_authorization.append(m_uri.to_string());
    m_authorization.append("\", qop=");
    m_authorization.append(m_qop == auth_int ? "auth-int" : "auth");
    m_authorization.append(", algorithm=MD5, nc=");
    m_authorization.append(m_nonceCount);
    m_authorization.append(", cnonce=\"");
    m_authorization.append(m_cnonce);
    m_authorization.append("\", response=\"");
    m_authorization.append(m_response);
    if (!m_opaque.empty()) {
      m_authorization.append("\", opaque=\"");
      m_authorization.append(m_opaque.to_string());
    }
    m_authorization.append("\"");
    return true;
  }

  static std::string generateNonce() {
    std::random_device rd;
    std::uniform_int_distribution<size_t> length{8, 32};
    std::uniform_int_distribution<int> distNum{0, 15};

    std::string nonce;
    nonce.resize(length(rd));
    for (char &val : nonce) {
      std::stringstream num;
      num << std::hex << distNum(rd);
      val = num.str()[0];
    }
    return nonce;
  }

  inline std::string authorization() const {
    return m_authorization;
  }

private:
  typedef unsigned char MD5_hash[MD5_DIGEST_LENGTH];
  boost::string_view m_authenticate;
  boost::string_view m_username;
  boost::string_view m_password;
  boost::string_view m_realm;
  boost::string_view m_nonce;
  boost::string_view m_opaque;
  boost::string_view m_algorithm;
  boost::string_view m_uri;
  boost::string_view m_method;
  boost::string_view m_body;

  enum QualityOfProtection { none, auth, auth_int };
  QualityOfProtection m_qop;
  std::string m_cnonce;
  std::string m_nonceCount;
  std::string m_ha1;
  std::string m_ha2;
  std::string m_response;
  std::string m_authorization;

  static std::string updateNonceCount() {
    static int nonceCount{};
    boost::cnv::strtol cnv;
    return boost::convert<std::string>(++nonceCount, cnv(boost::cnv::ARG::width = 8)(boost::cnv::ARG::fill = '0')).value();
  }

  inline bool findNonce() {
    return findSection("nonce", m_nonce);
  }

  inline bool findRealm() {
    return findSection("realm", m_realm);
  }

  inline bool findOpaque() {
    return findSection("opaque", m_opaque);
  }

  inline bool findAlgorithm() {
    return findSection("algorithm", m_algorithm);
  }

  bool findQop() {
    boost::string_view qop;
    if (findSection("qop", qop)) {
      // auth-int only with response body - working with tested implementations
      if (boost::iequals(qop, "auth-int") && !m_body.empty()) {
        m_qop = auth_int;
      } else {
        m_qop = auth;
      }
    }
    return false;
  }
  bool findSection(const std::string &key, boost::string_view &value) {
    boost::regex reg{key + "=([^,]+)"};
    boost::string_view::const_iterator start, end;
    start = m_authenticate.cbegin();
    end = m_authenticate.cend();
    boost::match_results<boost::string_view::const_iterator> matches;
    boost::match_flag_type flags = boost::match_default;
    if (boost::regex_search(start, end, matches, reg, flags)) {
      size_t size = static_cast<size_t>(std::distance(matches[1].first, matches[1].second));
      start = matches[1].first;
      end = matches[1].second - 1;
      // Trim quotes if they are there.
      if (*start == '"') {
        ++start;
        --size;
      }
      if (*end == '"') {
        --size;
      }
      value = boost::string_view(start, size);
      return true;
    }
    //  BOOST_LOG_TRIVIAL(warning) << "Digest request without " << key;
    return false;
  }

  void calculateHA1(MD5_hash ha1) {
    MD5_CTX Md5Ctx;
    MD5_Init(&Md5Ctx);
    MD5_Update(&Md5Ctx, m_username.data(), m_username.size());
    MD5_Update(&Md5Ctx, ":", 1);
    MD5_Update(&Md5Ctx, m_realm.data(), m_realm.size());
    MD5_Update(&Md5Ctx, ":", 1);
    MD5_Update(&Md5Ctx, m_password.data(), m_password.size());
    MD5_Final(ha1, &Md5Ctx);
    if (boost::iequals(m_algorithm, "md5-sess")) {
      MD5_Init(&Md5Ctx);
      MD5_Update(&Md5Ctx, ha1, MD5_DIGEST_LENGTH);
      MD5_Update(&Md5Ctx, ":", 1);
      MD5_Update(&Md5Ctx, m_nonce.data(), m_nonce.size());
      MD5_Update(&Md5Ctx, ":", 1);
      MD5_Update(&Md5Ctx, m_cnonce.data(), m_cnonce.size());
      MD5_Final(ha1, &Md5Ctx);
    };
  }
  void calculateHA2(MD5_hash ha2) {
    MD5_CTX Md5Ctx;

    // calculate H(A2)
    MD5_Init(&Md5Ctx);
    MD5_Update(&Md5Ctx, m_method.data(), m_method.size());
    MD5_Update(&Md5Ctx, ":", 1);
    MD5_Update(&Md5Ctx, m_uri.data(), m_uri.size());
    if (m_qop == auth_int) {
      MD5_Update(&Md5Ctx, ":", 1);
      // TODO: resolve this, it's probably wrong.
      MD5_Update(&Md5Ctx, m_body.data(), m_body.size());
    };
    MD5_Final(ha2, &Md5Ctx);
  }
  void calculateResponse(MD5_hash result) {
    MD5_CTX Md5Ctx;
    // calculate response
    MD5_Init(&Md5Ctx);
    MD5_Update(&Md5Ctx, m_ha1.data(), m_ha1.size());
    MD5_Update(&Md5Ctx, ":", 1);
    MD5_Update(&Md5Ctx, m_nonce.data(), m_nonce.size());
    MD5_Update(&Md5Ctx, ":", 1);
    if (m_qop != none) {
      MD5_Update(&Md5Ctx, m_nonceCount.data(), m_nonceCount.size());
      MD5_Update(&Md5Ctx, ":", 1);
      MD5_Update(&Md5Ctx, m_cnonce.data(), m_cnonce.size());
      MD5_Update(&Md5Ctx, ":", 1);
      if (m_qop == auth_int) {
        MD5_Update(&Md5Ctx, "auth-int", 8);
      } else {
        MD5_Update(&Md5Ctx, "auth", 4);
      }
      MD5_Update(&Md5Ctx, ":", 1);
    };
    MD5_Update(&Md5Ctx, m_ha2.data(), m_ha2.size());
    MD5_Final(result, &Md5Ctx);
  }

};

} // namespace simple_http

#endif // DIGESTAUTHENTICATOR_H
