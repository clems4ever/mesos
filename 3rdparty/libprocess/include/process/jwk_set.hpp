// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License

#ifndef __PROCESS_JWK_SET_HPP__
#define __PROCESS_JWK_SET_HPP__

#include <map>
#include <memory>
#include <string>

#include <process/jwk.hpp>

#include <stout/nothing.hpp>
#include <stout/try.hpp>

namespace process {
namespace http {
namespace authentication {

/**
 * JwkSet represents a set of signers and verifiers being key
 * holders able to sign messages and verify signatures.
 *
 * JWK sets are defined in
 * <a href="https://tools.ietf.org/html/rfc7517">rfc7517</a>
 */
class JwkSet {
public:
  /**
   * @constructor
   *
   * @param signers The map of signers by key ID derived from
   *   the key set.
   * @param verifiers The map of verifiers by key ID derived
   *   from the key set.
   */
  JwkSet(
    std::map<std::string, std::unique_ptr<Signer>>&& signers,
    std::map<std::string, std::unique_ptr<Verifier>>&& verifier);

  /**
   * Finds a signer based on its key ID.
   *
   * @param kid The key ID of the signer to find.
   * @return The signer associated to the key id
   *   otherwise an Error.
   */
  Try<Signer*> findSigner(const std::string& kid) const;

  /**
   * Finds a verifier based on its key ID.
   *
   * @param kid The key ID of the verifier to find.
   * @return The verifier associated with the key id
   *   otherwise an Error.
   */
  Try<Verifier*> findVerifier(const std::string& kid) const;

  /**
   * Accessor of signers.
   * @return The map of signers by key ID.
   */
  inline const std::map<std::string, std::unique_ptr<Signer>>& signers() const {
    return m_signers;
  }

  /**
   * Accessor of verifiers.
   * @return The map of verifiers by key ID.
   */
  inline
  const std::map<std::string, std::unique_ptr<Verifier>>& verifiers() const {
    return m_verifiers;
  }
 
/**
 * Convert a JSON representation of JWK set into an actual set of
 * signers and verifiers based on the following RFCs:
 * @see <a href="https://tools.ietf.org/html/rfc7517">rfc7517</a>
 * @see <a href="https://tools.ietf.org/html/rfc7518">rfc7518</a>
 *
 * This implementation only supports 'RSA' keys for the moment.
 *
 * @param jwkSet The string representing the JWK set containing keys
 *   to convert verifiers and signers.
 *
 * @return A JWK set if successful otherwise an Error.
 */
  static Try<JwkSet> parse(const std::string& jwkSet);

private:
  // The map of signers by key ID.
  std::map<std::string, std::unique_ptr<Signer>> m_signers;

  // The map of verifiers by key ID.
  std::map<std::string, std::unique_ptr<Verifier>> m_verifiers;
};


} // namespace authentication {
} // namespace http {
} // namespace process {

#endif // __PROCESS_JWK_SET_HPP__
