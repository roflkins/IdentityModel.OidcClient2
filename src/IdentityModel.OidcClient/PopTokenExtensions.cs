using System;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;

namespace IdentityModel.OidcClient
{
    public static class PopTokenExtensions
    {
        /// <summary>
        /// Outputs a signed B64 string for the token specified, using the key attached to the token.
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public static string ToSignedB64String(this JwtSecurityToken token)
        {
            var handler = new JwtSecurityTokenHandler();
            handler.OutboundClaimTypeMap.Clear();

            return handler.WriteToken(token);
        }


        internal static Tuple<Jwk.JsonWebKey, RsaSecurityKey> CreateProviderForPopToken()
        {
            var rsa = RSA.Create();
            rsa.KeySize = 2048; //Set explicitly - on iOS initalizes to 1024.
            var key = new RsaSecurityKey(rsa);
            key.KeyId = CryptoRandom.CreateUniqueId();

            var parameters = key.Rsa?.ExportParameters(false) ?? key.Parameters;
            var exponent = Base64Url.Encode(parameters.Exponent);
            var modulus = Base64Url.Encode(parameters.Modulus);

            var webKey = new Jwk.JsonWebKey
            {
                Kty = "RSA",
                Alg = "RS256",
                Kid = key.KeyId,
                E = exponent,
                N = modulus,
            };

            return new Tuple<Jwk.JsonWebKey, RsaSecurityKey>(webKey, key);
        }
    }
}
