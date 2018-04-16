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

#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <string>

#include <openssl/err.h>
#include <openssl/rsa.h>

#include <process/jwk_set.hpp>
#include <process/ssl/utilities.hpp>

#include <stout/gtest.hpp>

#include <process/jwt.hpp>

using std::map;
using std::shared_ptr;
using std::string;

using namespace process::http::authentication;

bool isValidRSAPublicKeyOnly(RSA *rsa) {
  const BIGNUM *n, *e;
  RSA_get0_key(rsa, &n, &e, nullptr);
  if (!rsa || !n || !e) {
      return false;
  }
  return BN_is_odd(e) && !BN_is_one(e);
}

TEST(JWKTest, BadJWKSet)
{
  // Invalid JWK Set.
  {
    string jwk = "{\"id\":\"test-jwk\",\"abc\":\"\"";
    Try<JwkSet> jwkSet = JwkSet::parse(jwk);
    EXPECT_ERROR(jwkSet);
  }

  // JWK set not having 'keys' key.
  {
    string jwk = "{\"id\":\"test-jwk\"}";
    Try<JwkSet> jwkSet = JwkSet::parse(jwk);
    EXPECT_ERROR(jwkSet);
  }

  // JWK set containing 'keys' for which the value is not an array.
  {
    string jwk = "{\"id\":\"test-jwk\",\"keys\":\"string\"}";
    Try<JwkSet> jwkSet = JwkSet::parse(jwk);
    EXPECT_ERROR(jwkSet);
  }
}

TEST(JWKTest, OneKeyInJWKSet)
{
  // JWK set containing one key without 'kty'.
  {
    string jwk = "{\"id\":\"test-jwk\",\"keys\":[{\"kid\":\"abc\"}]}";
    Try<JwkSet> jwkSet = JwkSet::parse(jwk);
    EXPECT_EQ(0, jwkSet->signers().size());
    EXPECT_EQ(0, jwkSet->verifiers().size());
  }

  // JWK set containing one key without 'kid'.
  {
    string jwk = "{\"id\":\"test-jwk\",\"keys\":[{\"kty\":\"abc\"}]}";
    Try<JwkSet> jwkSet = JwkSet::parse(jwk);
    EXPECT_EQ(0, jwkSet->signers().size());
    EXPECT_EQ(0, jwkSet->verifiers().size());
  }

  // JWK set containing one key with unsupported key type.
  {
    string jwk = "{\"id\":\"test-jwk\",\"keys\":"
               "[{\"kid\":\"abc\",\"kty\":\"EC\"}]}";
    Try<JwkSet> jwkSet = JwkSet::parse(jwk);
    EXPECT_EQ(0, jwkSet->signers().size());
    EXPECT_EQ(0, jwkSet->verifiers().size());
  }

  // JWK set containing one key with invalid RSA key (missing 'e').
  {
    string jwk = "{\"id\":\"test-jwk\",\"keys\":"
               "[{\"kid\":\"abc\",\"kty\":\"RSA\",\"n\":\"abc\"}]}";
    Try<JwkSet> jwkSet = JwkSet::parse(jwk);
    EXPECT_EQ(0, jwkSet->signers().size());
    EXPECT_EQ(0, jwkSet->verifiers().size());
  }

  // JWK set containing one key with invalid RSA key (missing 'n').
  {
    string jwk = "{\"id\":\"test-jwk\",\"keys\":"
               "[{\"kid\":\"abc\",\"kty\":\"RSA\",\"e\":\"abc\"}]}";
    Try<JwkSet> jwkSet = JwkSet::parse(jwk);
    EXPECT_EQ(0, jwkSet->signers().size());
    EXPECT_EQ(0, jwkSet->verifiers().size());
  }

  // JWK set containing one RSA public key with invalid base64 paremeters.
  {
    string jwk = "{\"id\":\"test-jwk\",\"keys\":"
               "[{\"kid\":\"abc\",\"kty\":\"RSA\","
               "\"n\":\"a(bc\",\"e\":\"a)bc\"}]}";
    Try<JwkSet> jwkSet = JwkSet::parse(jwk);
    EXPECT_EQ(0, jwkSet->signers().size());
    EXPECT_EQ(0, jwkSet->verifiers().size());
  }

  // JWK set containing one valid RSA public key.
  {
    string json = R"({
  "id":"test-jwk",
  "keys":[{
    "kid": "mesos.com",
    "kty": "RSA",
    "use": "sig",
    "n": "ALhQ-ZVQM9gIxRI8yFjMAY7S60DcWl8tsJPWIsIPFDnmCXr5Bt__lFlwBLM7q6ie5av-LkjwG0xAm7cohOHU7xEhZqh6n8CmJPlRbz_E8uFYfW67eP0YmdcS9dDBYn_77t_Ji7L0T2w62k7rE_vZ4k0MoSQnYkRq6uYZoltwaAO_3pab6dPov9HtRcTERHDTlKkNR4WDBZ9zLJKo2UbNoIoJpJ0D1T6CQXQVkFRiGFW-dnd-IZi4b2Dw93-ISR0vpmb0uVuo3pAlyuBwIXgzcTrwROFdXbSC3STyRLMd1Gvdc_CBGmGvIsGzld8no3WVWdzR0sZrawEWAaaOSvQcOI0",
    "e": "AQAB"
  }]
})";
    Try<JwkSet> jwkSet = JwkSet::parse(json);
    EXPECT_SOME(jwkSet);
    EXPECT_EQ(0, jwkSet->signers().size());
    EXPECT_EQ(1, jwkSet->verifiers().size());

    Try<Verifier*> mesosKeyVerifier = jwkSet.get().findVerifier("mesos.com");
    CHECK_NOTNULL(mesosKeyVerifier.get());
  }

  // JWK set containing one valid RSA private key based on all RSA params.
  {
    string json = R"({
  "id": "some-keys",
  "keys": [{
    "kid": "mesos.com",
    "kty": "RSA",
    "n": "ALhQ-ZVQM9gIxRI8yFjMAY7S60DcWl8tsJPWIsIPFDnmCXr5Bt__lFlwBLM7q6ie5av-LkjwG0xAm7cohOHU7xEhZqh6n8CmJPlRbz_E8uFYfW67eP0YmdcS9dDBYn_77t_Ji7L0T2w62k7rE_vZ4k0MoSQnYkRq6uYZoltwaAO_3pab6dPov9HtRcTERHDTlKkNR4WDBZ9zLJKo2UbNoIoJpJ0D1T6CQXQVkFRiGFW-dnd-IZi4b2Dw93-ISR0vpmb0uVuo3pAlyuBwIXgzcTrwROFdXbSC3STyRLMd1Gvdc_CBGmGvIsGzld8no3WVWdzR0sZrawEWAaaOSvQcOI0",
    "e": "AQAB",
    "d": "bzSD8V-LeBuKc39yzYiApCCDygVpDSXu9LNtEzKv3GL7c1OOn1V_txqL62vkHP-JyOS6Hk2n2rDcgnyS-AJWHzrMynf5rO1RP4-vlIUKmYWfYFECJYpTP110LHiRKnDhZeofPGCFDuLPVnAlBX4nOJ-XFc4hTvBHO39Z4tuGFkQFy5nMz6b24ku29NB3_-bebdpAbsY-tMIeY0-mtH9T3ysKv0OuNfRUvpHGfh_xgyHh1lnS70cuQEqxF46DuIsi0FoU-GOZkPyHQdoSNo1sy8fx4F6EOBa3mvuw3p2JwXWOgHu6oqmfhSSRVy_6JwhC8t9Gx-MBP_Fq05ufHZIMoQ",
    "p": "AOW4429p2EoIXZCWn04JViHKjL9buGP_xPVKdpnVKwyKdI8WgEa15Gu4ok0T4WbGXMumfS2iSCdVcaKACycR0B4favTNFwAmfhcygTNw4yAtCScfJOQR7ic24nTbZG37V_x_6tpoyrgC9H6IGRX63LVJjCpc0WWj-HZUDmCdBZ1J",
    "q": "AM1mbzS42560BHugeJ441KYYdkZWxUErct17FX7R3L2jR2f0Q2myghgxBSDL4oq7twSerL1xJSZ6p6bERwgxNBFvJgd8L4L6nSdXF20Td-RHREbtOg66Rvgmo4EgUVzCr0B8WWWyBeGj-YS-huUEqpSxZul9tKlqiezlavq0uZUl",
    "dp": "ALffsqQWG5q-cW3vMhn7XSb1Ao2Us9XO_u67qIzfVHLYTA3QG-L9apVSlw6M8Ckcc2BKpf2l3I0nViqUxNiD6IqD6U-C7XsgVGLq-QGcxR-XDLF0u0mWlIJs6vxQM2XY_gdMuEYUBNce_mZdN38hahHtibTK0IzDn3fPNibc6IaJ",
    "dq": "THATcHZe3Le3d15npNIXaNxvn4uJCtClhYDZpgFpeXU7DJedQsd4nJIZi3P0kZZ77I80T6e8oI5Ct9ARcx4Ed3x6lYyEjeS_-TTy9dep5V0ULqT31yVBZfXTISmqva-B0qi0CCFxCOCh6eGRh8btyDogx0HNqsKII43Y-wWojrU",
    "qi": "HwH4IZi4eIOcKC_ChC7LgkwCg7bAmGJrAKgSJJOTH0vU5UFcS1qqLpwkShDlFJiVJseEdeu4TjGjj_BiSdFxiMdgvmCeYh7drWDmQSuX39W1bJHgstjFX9-fNOGn5Xh2z6k-6sjPPr1lyl2U4YAWMFqvIWA6MOZokPiW0rW1HUA"
  }]
})";

    Try<JwkSet> jwkSet = JwkSet::parse(json);
    EXPECT_SOME(jwkSet);
    EXPECT_EQ(1, jwkSet->signers().size());
    EXPECT_EQ(0, jwkSet->verifiers().size());

    Try<Signer*> mesosKeySigner = jwkSet.get().findSigner("mesos.com");
    CHECK_NOTNULL(mesosKeySigner.get());
  }

  // JWK set containing one valid RSA private key based on partial RSA params.
  {
    // We provide only minimal set of parameters to create the private key.
    string json = R"({
  "id": "some-keys",
  "keys": [{
    "kid": "mesos.com",
    "kty": "RSA",
    "n": "ALhQ-ZVQM9gIxRI8yFjMAY7S60DcWl8tsJPWIsIPFDnmCXr5Bt__lFlwBLM7q6ie5av-LkjwG0xAm7cohOHU7xEhZqh6n8CmJPlRbz_E8uFYfW67eP0YmdcS9dDBYn_77t_Ji7L0T2w62k7rE_vZ4k0MoSQnYkRq6uYZoltwaAO_3pab6dPov9HtRcTERHDTlKkNR4WDBZ9zLJKo2UbNoIoJpJ0D1T6CQXQVkFRiGFW-dnd-IZi4b2Dw93-ISR0vpmb0uVuo3pAlyuBwIXgzcTrwROFdXbSC3STyRLMd1Gvdc_CBGmGvIsGzld8no3WVWdzR0sZrawEWAaaOSvQcOI0",
    "e": "AQAB",
    "d": "bzSD8V-LeBuKc39yzYiApCCDygVpDSXu9LNtEzKv3GL7c1OOn1V_txqL62vkHP-JyOS6Hk2n2rDcgnyS-AJWHzrMynf5rO1RP4-vlIUKmYWfYFECJYpTP110LHiRKnDhZeofPGCFDuLPVnAlBX4nOJ-XFc4hTvBHO39Z4tuGFkQFy5nMz6b24ku29NB3_-bebdpAbsY-tMIeY0-mtH9T3ysKv0OuNfRUvpHGfh_xgyHh1lnS70cuQEqxF46DuIsi0FoU-GOZkPyHQdoSNo1sy8fx4F6EOBa3mvuw3p2JwXWOgHu6oqmfhSSRVy_6JwhC8t9Gx-MBP_Fq05ufHZIMoQ"
  }]
})";

    Try<JwkSet> jwkSet = JwkSet::parse(json);
    EXPECT_SOME(jwkSet);

    Try<Signer*> mesosKeySigner = jwkSet.get().findSigner("mesos.com");
    CHECK_NOTNULL(mesosKeySigner.get());
  }
}

TEST(JWKTest, SeveralKeysInJWKSet)
{
  // JWK set containing valid RSA private keys based on partial RSA params.
  {
    // We provide only minimal set of parameters to compute the private key.
    string json = R"({
  "id": "some-keys",
  "keys": [{
    "kid": "mesos.com",
    "kty": "RSA",
    "n": "ALhQ-ZVQM9gIxRI8yFjMAY7S60DcWl8tsJPWIsIPFDnmCXr5Bt__lFlwBLM7q6ie5av-LkjwG0xAm7cohOHU7xEhZqh6n8CmJPlRbz_E8uFYfW67eP0YmdcS9dDBYn_77t_Ji7L0T2w62k7rE_vZ4k0MoSQnYkRq6uYZoltwaAO_3pab6dPov9HtRcTERHDTlKkNR4WDBZ9zLJKo2UbNoIoJpJ0D1T6CQXQVkFRiGFW-dnd-IZi4b2Dw93-ISR0vpmb0uVuo3pAlyuBwIXgzcTrwROFdXbSC3STyRLMd1Gvdc_CBGmGvIsGzld8no3WVWdzR0sZrawEWAaaOSvQcOI0",
    "e": "AQAB",
    "d": "bzSD8V-LeBuKc39yzYiApCCDygVpDSXu9LNtEzKv3GL7c1OOn1V_txqL62vkHP-JyOS6Hk2n2rDcgnyS-AJWHzrMynf5rO1RP4-vlIUKmYWfYFECJYpTP110LHiRKnDhZeofPGCFDuLPVnAlBX4nOJ-XFc4hTvBHO39Z4tuGFkQFy5nMz6b24ku29NB3_-bebdpAbsY-tMIeY0-mtH9T3ysKv0OuNfRUvpHGfh_xgyHh1lnS70cuQEqxF46DuIsi0FoU-GOZkPyHQdoSNo1sy8fx4F6EOBa3mvuw3p2JwXWOgHu6oqmfhSSRVy_6JwhC8t9Gx-MBP_Fq05ufHZIMoQ"
  }, {
    "kid": "apache.mesos.com",
    "kty": "RSA",
    "n": "AODuL8Bb2xhY69Ctr4dLtDHi0poz74b_KaWgas7ZP807nIP1pNF23VMLDPpRuHmnnUdvDB2GOMuDP8tdj8JdUzFCjyzYe9UTMB1VQg7RpSih9DceegSMxo6hipEqUmVpE-TZPrcBGq0Faf-iXGBgJ2ad6RvMkWlSyJeg_nwYqJxP3zVdIO2FowaNVBlk00QQaBZQypO4Itv82u__QPEVJ0PVljHnPznCa0kqBTGzIAUrzHCGxrgtJLmefWLRTnO9_-GDmPJs-yVGSFSK8IhWb4xh8FgMkT-TdkX6DDUdsVQ24nUelf6JpUxEaEHRc30TES3qOfDNyMJA2QKXsCedd6k",
    "e": "AQAB",
    "d": "ANaHFhAXC84a8T6kiSc3MvPpbAgaxLcyolwPtg728X0i_9Jz9PC6t7i-b3BHhPSywrUg2qNGIuEnmy6xW617KR9wZfHVv7WniVpQuKI9nZI1dSEk9idkxPPAatKtVMzX_VtlQAV3DiQ7Z6-jAQwCaVHcBjq3T3DuvdawfEeLlTUOxp4fokUbC4upFVXpIDHpn4aEA88xpmdUyltLvQhUCdoXyCxp8-5x4lmarUaKAxs785y6qeiQ8Dno2UmO5pDHfINxCiS7mch5CGskUm8JUkBP_ICipanScejh8_lOnYm5UX0zm6Q4Zvbr2u0z8Mbbjfwf2_V1nzQsj0u8b7YrlCk"
}]
})";

    Try<JwkSet> jwkSet = JwkSet::parse(json);
    EXPECT_SOME(jwkSet);
    EXPECT_TRUE(jwkSet->signers().size() == 2);

    Try<Signer*> mesosKeySigner = jwkSet.get().findSigner("mesos.com");
    CHECK_NOTNULL(mesosKeySigner.get());

    Try<Signer*> apacheMesosKeySigner = jwkSet.get().findSigner("apache.mesos.com");
    CHECK_NOTNULL(apacheMesosKeySigner.get());
  }

  // JWK set containing valid RSA private keys based on complete RSA params.
  {
    // We provide all parameters of the private keys.
    string json = R"({
  "id": "some-keys",
  "keys": [{
    "kid": "mesos.com",
    "kty": "RSA",
    "n": "ALS7hnniRl-gU5TF0gLlaBLPeDBhlCGVjCu98bjvRTT9HPaNqUYKcirYUJpLGncZMk2H-gERPBR_AKBk7KSTFk8Nw8uaaIWVvJ-SvpKD-GcpSZzHW-DHBVxPqrDJh8k8EcKLS-f0AtklGpBDPntg3P6DF3OXhD3kW4M8Inm_o7_M3eqQXXEWC2TvAm8Zf1s_vvpJyfFR0PNOzEFk3Zl4eQXwkTMpTaLHsfYoQW4v3INc1BmTxNi8mYJyOy7slminGOSQc82FC_H6R4EA2i8aRfIQfS1wST4Rf6o03wkScDgBMdhUQUrHzWOJ2o2wYuiDulr6SL1XZU0yDpJ55mMGGSM",
    "e": "AQAB",
    "d": "NzCwvxWfIeKGw36pRCMj5eKfND8ICj1twYnOgAfpHWZR6uSVlYLpHDZUXtmiak4yc0SbzqmhrCygV1qafSNBg8CTUuCDHI_-OsiIE5vjRjVwekTSxNBhza-yUywnoAcM8ViyRFHacM8IzpcKRIju03XaunzBcFkErQ23BXDFI3N7LMJ0Q_o-5dAguj4919ZERckqRGYFnynpx1iXZDRZcpvNe1_0BAGt8htdHgfd4x7g_PoIh5J8usGCQXpedF6Y0gJ3AXG_8XLR9tyBYCF4oznHcg2cwAESKIe6xXsrg9AL6JhFpB59auDjcacqqwt2SFyflwogaOv8Nid9q1p7aQ",
    "p": "AO03ALzJZYllFir5FWrxeXrEc6KitMrsGz1z9iSWlRlCqV-rhlHMA3xOTklkIJIOK9tgk1BkdM-xuNPa62mbyjYpN3r-ZJ8niC2UbqqRa9GBvGHeSR7vcqj5nnLi0d9VpBpM9G_weEwLEV1KIAMk8XmpNWftI49yY0cKLAN6IGvf",
    "q": "AMMLeGJ-pbAJMor2RAl88qOvz_y974reDnZxm-tJA_jDws-oi0neZOmCboqdOnAxg3NyrD2iVIzzCpEUk07eK1jx3_Zd9jUbJsdOgs6vaaa9VEOukMAXASdIUvFFEXEB8GrZNZoqGNbq0QDvQkoeIoAXnh63cP_cq5Z5e4Q9kDs9",
    "dp": "CTgRBEVDd_KAyQzDI1PdJ8NIxzJRmm1QpbPDBisAAmpP0NMGtlkabZNRgZKtnV-FntIDB6XP0F6U0073xTPzyOUTLemDGZhct4DESEa8jPjgzGDqMJSXvS9uVAKyq15VsVv6R_ttgW8QrrJ5ygV-iP7lf3N85U9JwnIHwd7WMbs",
    "dq": "aaeT_d7XCAXjcC04697YXV0GkMWeth3VvcmLCahS03XP2MdXNJuZFHkIQmQrXM0lhOtQbE67-GJLjg2UQnvNBXB4vq9liJz9o6de6nFRDPawZ71vQe70PABMlc-xRAMl5etlwu4c6Ibo0tXIlfe-_p5MlB0QxDkYZfnGs_rZX40",
    "qi": "AIhIq52pul7D8rPeLpsrhCZekiAzVmH_ARXZF4umFc95kEBmIelyUALICfLCts44smq0FXoFHOZkqpROD2ocgniJ0PqwPS6m0K2C-x11nx9YNijHDDNXCv6NmuX01GddwwOC2XuXZnQY5MkPhriDkbAjsdON-SS3y6f4_4s7dojl"
} , {
    "kid": "apache.mesos.com",
    "kty": "RSA",
    "n": "AOpT1NsW_MD8Qqxjx-DYckAQh0W1l5Y-i8VDJjctOtfO1CzVLk4quM2uqxvh7WS_Q6XrOXW5sxur6PT8KR_gy-WJBzizlPPpKik9GuAzH8gP1lka4bGLeGmiXimd3w57wkiOKdl2oGlB--qd7gtND4hPqFjDOcEzi_lPZltXweFDij9OqVs6q65VSKD7rQ1v5cHVl0Df0oNeFNpU7ORSV9iflusx7JdKLhUc_RpLnLafmF4X-HbL8CErOQVMbpHC8SMGNxEIiFNN9TpMarSBiFrJuWbsBbTucw9_RqoPLRXX_c30t-VbHpD-1sJfhKvacBLFm5C4kFThOLeov7qeAXM",
    "e": "AQAB",
    "d": "S2AF8yeUzBsY80zxaZEWRydJ7BF6nlimKyDrdQo2iF6-f2FfkMNLSNYrsj9dVm_zubZNeGHwjDEjMVK_g8KSs9X9Ha8edcsFxdgjAgVP7tGxWF4-RRcg95HECkz_CDClESOxsILpHJKeDx0YCkiSe31sIIlD1bLYDq0Mtssm0WeDyM8jn-uFTObkrTfGB4gPXIKU-Q6zYiwMnZ-ORb44d5ZE5dCNqpmPX3frYpv_rDyaiO7nilzpGPuU3JDd9XgKr6ngD7y7LNQFTvL-5pZy7-YeydZQQiMCYivLmJidQ4vyPmiSh9Nd1j7_GRnOAYFCVoDqirSbeGb5I4rlgkMFGQ",
    "p": "APbJ4Lrh_jhqoxmjQm0SqbPFmglNAdAw6C8NQ4XnDqrgMeMtkbS9TE1giacpPYTusyIVeAs1BeKFJulQQda-H5suNBmgpqqtu6e91tRF0DuHf3LYj2xvMSeigs49SuBv_TkMqLMNqISdf8zTmbtP7LJhnOEC2AxjMMBgfNjxRQZF",
    "q": "APMS4n43kt-ztOJyy4LNZHC2Xvi8aURWIoKH4jOFXT9jelZ25VV66psrqiSrIJirr7XQC5MJ4hZUcjaRbWlfi3vZGieF3e0fg_i2ORDI2tZMmrgG2YHLFeBK2SjXxiKB60MeEH3WQPo7CVOL1u6crOI8MEHZ3r2EV7fCrb2bA2BX",
    "dp": "AL1GqC2tFqV-ZAlNxaySG8XdT_7CKRnb6LftnFQemolD2f86-_17EgJmgCzM3HoP-SOzA5bU2-aX6PgYreZdezAxh5QAOtO826gTWakEwmhly8Hxhk7MGQ8k_N3g9ISeX8BZjSmG2DCd-17FC6s16XwGkaOh4sHdcY6aciaRJTdh",
    "dq": "cciHSXoOQLVImTAPX91xhOl5r4nS5PBFG0Ese92T9tZEMDFbzRXKuHRKIvwQOCc2Cy-mG2Bm-vjwteaBhu_4xTKtcY7SgetcxZHXSKoc9m_JhRd_vagpR2MCIIJQ91pFnJd4NM-Ufw4foYI2TF_-9bAjDtBD2gcXYKe62KS1geU",
    "qi": "OjMZpjbllN4AAXtr_qyyMlT3o8stqmn3e2vOErxbAR80j7gm8KXmXHchu7epSWpkfwk3bSeA5qKIGnYJ4-EngYXRYWKqmQ4im5PYkH4QKbGdn3ylWTUP-Y3wBMwr8N6-uCKG0o2tuD-GDpUKjDaqrVCHi8Sc6BvCF-KvVphBEts"
}]
})";

    Try<JwkSet> jwkSet = JwkSet::parse(json);
    EXPECT_SOME(jwkSet);
    EXPECT_TRUE(jwkSet->signers().size() == 2);

    Try<Signer*> mesosKeySigner = jwkSet.get().findSigner("mesos.com");
    CHECK_NOTNULL(mesosKeySigner.get());

    Try<Signer*> apacheMesosKeySigner = jwkSet.get().findSigner("apache.mesos.com");
    CHECK_NOTNULL(apacheMesosKeySigner.get());
  }

  // JWK set containing one valid RSA private key and one valid RSA public key.
  {
    string json = R"({
  "id": "some-keys",
  "keys": [{
    "kid": "mesos.com",
    "kty": "RSA",
    "n": "ALS7hnniRl-gU5TF0gLlaBLPeDBhlCGVjCu98bjvRTT9HPaNqUYKcirYUJpLGncZMk2H-gERPBR_AKBk7KSTFk8Nw8uaaIWVvJ-SvpKD-GcpSZzHW-DHBVxPqrDJh8k8EcKLS-f0AtklGpBDPntg3P6DF3OXhD3kW4M8Inm_o7_M3eqQXXEWC2TvAm8Zf1s_vvpJyfFR0PNOzEFk3Zl4eQXwkTMpTaLHsfYoQW4v3INc1BmTxNi8mYJyOy7slminGOSQc82FC_H6R4EA2i8aRfIQfS1wST4Rf6o03wkScDgBMdhUQUrHzWOJ2o2wYuiDulr6SL1XZU0yDpJ55mMGGSM",
    "e": "AQAB",
    "d": "NzCwvxWfIeKGw36pRCMj5eKfND8ICj1twYnOgAfpHWZR6uSVlYLpHDZUXtmiak4yc0SbzqmhrCygV1qafSNBg8CTUuCDHI_-OsiIE5vjRjVwekTSxNBhza-yUywnoAcM8ViyRFHacM8IzpcKRIju03XaunzBcFkErQ23BXDFI3N7LMJ0Q_o-5dAguj4919ZERckqRGYFnynpx1iXZDRZcpvNe1_0BAGt8htdHgfd4x7g_PoIh5J8usGCQXpedF6Y0gJ3AXG_8XLR9tyBYCF4oznHcg2cwAESKIe6xXsrg9AL6JhFpB59auDjcacqqwt2SFyflwogaOv8Nid9q1p7aQ",
    "p": "AO03ALzJZYllFir5FWrxeXrEc6KitMrsGz1z9iSWlRlCqV-rhlHMA3xOTklkIJIOK9tgk1BkdM-xuNPa62mbyjYpN3r-ZJ8niC2UbqqRa9GBvGHeSR7vcqj5nnLi0d9VpBpM9G_weEwLEV1KIAMk8XmpNWftI49yY0cKLAN6IGvf",
    "q": "AMMLeGJ-pbAJMor2RAl88qOvz_y974reDnZxm-tJA_jDws-oi0neZOmCboqdOnAxg3NyrD2iVIzzCpEUk07eK1jx3_Zd9jUbJsdOgs6vaaa9VEOukMAXASdIUvFFEXEB8GrZNZoqGNbq0QDvQkoeIoAXnh63cP_cq5Z5e4Q9kDs9",
    "dp": "CTgRBEVDd_KAyQzDI1PdJ8NIxzJRmm1QpbPDBisAAmpP0NMGtlkabZNRgZKtnV-FntIDB6XP0F6U0073xTPzyOUTLemDGZhct4DESEa8jPjgzGDqMJSXvS9uVAKyq15VsVv6R_ttgW8QrrJ5ygV-iP7lf3N85U9JwnIHwd7WMbs",
    "dq": "aaeT_d7XCAXjcC04697YXV0GkMWeth3VvcmLCahS03XP2MdXNJuZFHkIQmQrXM0lhOtQbE67-GJLjg2UQnvNBXB4vq9liJz9o6de6nFRDPawZ71vQe70PABMlc-xRAMl5etlwu4c6Ibo0tXIlfe-_p5MlB0QxDkYZfnGs_rZX40",
    "qi": "AIhIq52pul7D8rPeLpsrhCZekiAzVmH_ARXZF4umFc95kEBmIelyUALICfLCts44smq0FXoFHOZkqpROD2ocgniJ0PqwPS6m0K2C-x11nx9YNijHDDNXCv6NmuX01GddwwOC2XuXZnQY5MkPhriDkbAjsdON-SS3y6f4_4s7dojl"
} , {
    "kid": "apache.mesos.com",
    "kty": "RSA",
    "n": "AOpT1NsW_MD8Qqxjx-DYckAQh0W1l5Y-i8VDJjctOtfO1CzVLk4quM2uqxvh7WS_Q6XrOXW5sxur6PT8KR_gy-WJBzizlPPpKik9GuAzH8gP1lka4bGLeGmiXimd3w57wkiOKdl2oGlB--qd7gtND4hPqFjDOcEzi_lPZltXweFDij9OqVs6q65VSKD7rQ1v5cHVl0Df0oNeFNpU7ORSV9iflusx7JdKLhUc_RpLnLafmF4X-HbL8CErOQVMbpHC8SMGNxEIiFNN9TpMarSBiFrJuWbsBbTucw9_RqoPLRXX_c30t-VbHpD-1sJfhKvacBLFm5C4kFThOLeov7qeAXM",
    "e": "AQAB"
}]
})";

    Try<JwkSet> jwkSet = JwkSet::parse(json);
    EXPECT_SOME(jwkSet);
    EXPECT_TRUE(jwkSet->verifiers().size() == 1);
    EXPECT_TRUE(jwkSet->signers().size() == 1);

    Try<Signer*> mesosKeySigner = jwkSet.get().findSigner("mesos.com");
    CHECK_NOTNULL(mesosKeySigner.get());

    Try<Verifier*> apacheMesosKeyVerifier = jwkSet.get().findVerifier("apache.mesos.com");
    CHECK_NOTNULL(apacheMesosKeyVerifier.get());
  }
}
