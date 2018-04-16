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

#ifndef __PROCESS_JWK_RSA_HPP__
#define __PROCESS_JWK_RSA_HPP__

#include <string>

#include <openssl/rsa.h>

#include <process/jwk.hpp>

#include <stout/nothing.hpp>
#include <stout/try.hpp>

namespace process {
namespace http {
namespace authentication {

/**
 * RSASigner holds a private RSA key and sign messages with
 * this key.
 */
class RSASigner : public Signer {
public:
  /**
   * @constructor
   *
   * RSASigner needs a private key to generate signatures.
   */
  RSASigner(std::shared_ptr<RSA> privateKey);
  /**
   * Computes the signature of a given message.

   * @param message The message to compute signature of.
   * @return The signature.
   */
  Try<std::string> sign(const std::string& message) const override;

private:
  std::shared_ptr<RSA> m_privateKey;
};

/**
 * RSAVerifier holds a public RSA key and verify signatures
 * of messages with this key.
 */
class RSAVerifier : public Verifier{
public:
  /**
   * RSAVerifier needs a public key to verify signatures.
   */
  RSAVerifier(std::shared_ptr<RSA> publicKey);
  /**
   * Verify the signature of a given message.
   *
   * @param message The message to verify the signature of.
   * @param signature The signature to verify.
   * @return Nothing if signature is valid otherwise an Error.
   */
  Try<Nothing> verify(
    const std::string& message,
    const std::string& signature) const override;

private:
  std::shared_ptr<RSA> m_publicKey;
};

} // namespace authentication {
} // namespace http {
} // namespace process {

#endif // __PROCESS_JWK_RSA_HPP__
