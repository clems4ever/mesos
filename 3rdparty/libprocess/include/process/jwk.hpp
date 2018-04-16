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

#ifndef __PROCESS_JWK_HPP__
#define __PROCESS_JWK_HPP__

#include <string>

#include <stout/nothing.hpp>
#include <stout/try.hpp>

namespace process {
namespace http {
namespace authentication {

/**
 * A signer holds a shared secret or a private key in order to
 * sign messages.
 *
 * Signer is a virtual interface that can be derived for each
 * type of key supported in the JWK RFC (RSA, Elliptic curves,
 * octet sequence keys).
 */
class Signer {
public:
  virtual ~Signer() {}
  /**
   * Computes the signature of a given message.

   * @param message The message to compute signature of.
   * @return The signature.
   */
  virtual Try<std::string> sign(const std::string& message) const = 0;
};


/**
 * A verifier holds a shared secret or a public key in order to
 * verify the signature of a given message.
 *
 * Verifier is a virtual interface that can be derived for each
 * type of key supported in the JWK RFC (RSA, Elliptic curves,
 * octet sequence keys).
 */
class Verifier {
public:
  virtual ~Verifier() {}
  /**
   * Verify the signature of a given message.
   *
   * @param message The message to verify the signature of.
   * @param signature The signature to verify.
   * @return Nothing if signature is valid otherwise an Error.
   */
  virtual Try<Nothing> verify(
    const std::string& message,
    const std::string& signature) const = 0;
};

} // namespace authentication {
} // namespace http {
} // namespace process {

#endif // __PROCESS_JWK_HPP__
