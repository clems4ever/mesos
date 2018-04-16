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

#include <process/jwk_set.hpp>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <process/jwk_rsa.hpp>

#include <stout/base64.hpp>
#include <stout/foreach.hpp>
#include <stout/json.hpp>

namespace process {
namespace http {
namespace authentication {

using std::map;
using std::pair;
using std::shared_ptr;
using std::string;
using std::unique_ptr;
using std::vector;

namespace {

typedef std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> BIGNUM_unique_ptr;

/**
 * Helper function finding a string in a JSON.
 */
Try<string> findStringValueInJson(const JSON::Object& json, const string& key)
{
  const Result<JSON::Value> value_json = json.find<JSON::Value>(key);
  if (value_json.isNone()) {
    return Error("Failed to locate '" + key + "' in JWK");
  }

  if (!value_json->is<JSON::String>()) {
    return Error("Token '" + key + "' is not a string");
  }
  return value_json->as<JSON::String>().value;
}

/**
 * Helper function extracting a big num from a JWK.
 */
Try<BIGNUM_unique_ptr> extractBigNum(
    const JSON::Object& jwk,
    const string& paramKey)
{
  Try<string> paramBase64 = findStringValueInJson(jwk, paramKey);
  if (paramBase64.isError()) {
    return Error(paramBase64.error());
  }

  Try<string> param = base64::decode_url_safe(paramBase64.get());
  if (param.isError()) {
    return Error("Failed to base64url-decode: " + param.error());
  }

  BIGNUM_unique_ptr paramBn(
    BN_bin2bn(
      reinterpret_cast<const unsigned char*>(param.get().c_str()),
      param.get().size(),
      nullptr),
    BN_free);

  if (!paramBn) {
    return Error("Failed to convert '" + paramKey +"' to BIGNUM");
  }

  return paramBn;
}

/**
 * Extract a set of BIGNUMs based on their key names. This function returns
 * an error if one required key is missing or add an null pointer to the
 * map if the key is optional.
 */
Try<map<string, BIGNUM_unique_ptr>> extractBigNums(
    const JSON::Object& jwk,
    const vector<string>& requiredKeys,
    const vector<string>& optionalKeys = vector<string>())
{
  map<string, BIGNUM_unique_ptr> bigNums;

  // Treat required keys.
  foreach (const string& key, requiredKeys) {
    Try<BIGNUM_unique_ptr> bigNum = extractBigNum(jwk, key);
    if (bigNum.isError()) {
      return Error(bigNum.error());
    }
    bigNums.insert(make_pair(key, move(bigNum.get())));
  }

  // Then treat optional keys.
  foreach (const string& key, optionalKeys) {
    Try<BIGNUM_unique_ptr> bigNum = extractBigNum(jwk, key);
    if (bigNum.isError()) {
      bigNums.insert(
        make_pair(key, move(BIGNUM_unique_ptr(nullptr, BN_free))));
    }
    else {
      bigNums.insert(make_pair(key, move(bigNum.get())));
    }
  }

  return bigNums;
}


Try<shared_ptr<RSA>> jwkToRSAPublicKey(const JSON::Object& jwk)
{
  // e is the public exponent.
  // n is the modulus.
  Try<map<string, BIGNUM_unique_ptr>> params = extractBigNums(jwk, {"e", "n"});
  if (params.isError()) {
    return Error("Failed to create RSA public key: " + params.error());
  }

  shared_ptr<RSA> rsaKey(RSA_new(), RSA_free);
  int success = RSA_set0_key(
    rsaKey.get(),
    params->at("n").release(),
    params->at("e").release(),
    nullptr);

  if (!success) {
    return Error("Failed to set public key parameters: " + params.error());
  }

  return rsaKey;
}


Try<shared_ptr<RSA>> jwkToRSAPrivateKey(
    const JSON::Object& jwk)
{
  // e is the public exponent (required).
  // n is the modulus (required).
  // d is the private exponent (required).

  // p and q are secret prime factors (optional).
  // dp is d mod (p-1) (optional).
  // dq is d mod (q-1) (optional).
  // qi is q^-1 mod p  (optional).
  Try<map<string, BIGNUM_unique_ptr>> params = extractBigNums(jwk,
    {"e", "n", "d"}, {"p", "q", "dp", "dq", "qi"});

  if (params.isError()) {
    return Error("Failed to create RSA private key: " + params.error());
  }

  shared_ptr<RSA> rsaKey(RSA_new(), RSA_free);
  int success = RSA_set0_key(
    rsaKey.get(),
    params->at("n").release(),
    params->at("e").release(),
    params->at("d").release());

  if (!success) {
    return Error("Failed to set private key parameters of RSA key.");
  }

  std::function<BIGNUM*(const string&)> findOrNullptr =
    [&params](const string& key) -> BIGNUM* {
      auto it = params->find(key);
      if (it == params->end()) {
        return nullptr;
      }
      return it->second.release();
    };

  BIGNUM *p = findOrNullptr("p");
  BIGNUM *q = findOrNullptr("q");
  
  if (p && q) {
    success = RSA_set0_factors(rsaKey.get(), p, q);

    if (!success) {
      return Error("Failed to set prime factors of RSA key.");
    }
  }

  BIGNUM *dp = findOrNullptr("dp");
  BIGNUM *dq = findOrNullptr("dq");
  BIGNUM *qi = findOrNullptr("qi");

  if (dp && dq && qi) {
    success = RSA_set0_crt_params(rsaKey.get(), dp, dq, qi);

    if (!success) {
      return Error("Failed to set CRT parameters of RSA key.");
    }
  }

  return rsaKey;
}

enum KeyType {
  PUBLIC,
  PRIVATE
};

Try<pair<shared_ptr<RSA>, KeyType>> jwkToRSAKey(const JSON::Object& jwk)
{
  Try<string> d = findStringValueInJson(jwk, "d");
  if (d.isSome()) {
    Try<shared_ptr<RSA>> privateKey = jwkToRSAPrivateKey(jwk);
    if (privateKey.isError()) {
      return Error(privateKey.error());
    }
    return make_pair(privateKey.get(), KeyType::PRIVATE);
  }

  Try<shared_ptr<RSA>> publicKey = jwkToRSAPublicKey(jwk);
  if (publicKey.isError()) {
    return Error(publicKey.error());
  }
  return make_pair(publicKey.get(), KeyType::PUBLIC);
}


Try<Nothing> parseAndClassifyJwk(
  const JSON::Object& jwk,
  map<string, unique_ptr<Signer>>& signers,
  map<string, unique_ptr<Verifier>>& verifiers)
{
  Try<string> kty = findStringValueInJson(jwk, "kty");
  if (kty.isError()) {
    return Error("Failed to parse JWK: " + kty.error());
  }

  Try<string> kid = findStringValueInJson(jwk, "kid");
  if (kid.isError()) {
    return Error("Failed to parse JWK: " + kid.error());
  }

  if (kty.get() == "RSA") {
    Try<pair<shared_ptr<RSA>, KeyType>> rsaKey = jwkToRSAKey(jwk);
    if (rsaKey.isError()) {
      return Error(rsaKey.error());
    }

    if (rsaKey->second == KeyType::PUBLIC) {
      unique_ptr<Verifier> verifier(new RSAVerifier(rsaKey->first));
      verifiers.insert(make_pair(kid.get(), move(verifier)));
    }
    else if (rsaKey->second == KeyType::PRIVATE) {
      unique_ptr<Signer> signer(new RSASigner(rsaKey->first));
      signers.insert(make_pair(kid.get(), move(signer)));
    }
  }

  return Error("Unsupported key type: " + kty.get());
}

}


JwkSet::JwkSet(
  map<string, unique_ptr<Signer>>&& signers,
  map<string, unique_ptr<Verifier>>&& verifiers)
  : m_signers(move(signers)), m_verifiers(move(verifiers)) {
}


Try<Signer*> JwkSet::findSigner(const string& kid) const {
  auto it = m_signers.find(kid); 
  if (it != m_signers.end()) {
    return it->second.get();
  }
  return Error("Signer with kid \"" + kid + "\" has not been found.");
}


Try<Verifier*> JwkSet::findVerifier(const string& kid) const {
  auto it = m_verifiers.find(kid); 
  if (it != m_verifiers.end()) {
    return it->second.get();
  }
  return Error("Verifier with kid \"" + kid + "\" has not been found.");
}


Try<JwkSet> JwkSet::parse(const string& jwk)
{
  const Try<JSON::Object> json = JSON::parse<JSON::Object>(jwk);
  if (json.isError()) {
    return Error("Failed to parse into JSON: " + json.error());
  }

  Result<JSON::Value> keys_json = json->find<JSON::Value>("keys");
  if (keys_json.isNone()) {
    return Error("Failed to locate 'keys' in JWK");
  }

  if (!keys_json->is<JSON::Array>()) {
    return Error("Token 'keys' is not an array");
  }

  map<string, unique_ptr<Signer>> signers;
  map<string, unique_ptr<Verifier>> verifiers;

  vector<JSON::Value> keys = keys_json->as<JSON::Array>().values;
  foreach (const JSON::Value& key_json, keys) {
    if (!key_json.is<JSON::Object>()) {
      return Error("'keys' must contain objects only");
    }

    Try<Nothing> res = parseAndClassifyJwk(key_json.as<JSON::Object>(), signers, verifiers);
    if (res.isError()) {
      LOG(WARNING) << res.error();
    }
  }
  return JwkSet(move(signers), move(verifiers));
}

} // namespace authentication {
} // namespace http {
} // namespace process {
