using System;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Threading.Tasks;

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


        internal static Task<Tuple<Jwk.JsonWebKey, RsaSecurityKey>> CreateProviderForPopTokenAsync()
        {
            return Task.Run(() =>
            {
                var rsa = RSA.Create();
                RSAParameters parameters;
                if (rsa.KeySize < 2048)
                {
                    rsa.Dispose();
                    rsa = new RSACryptoServiceProvider(2048);
                }
                RsaSecurityKey key = null;
                if (rsa is RSACryptoServiceProvider)
                {
                    parameters = rsa.ExportParameters(includePrivateParameters: true);
                    key = new RsaSecurityKey(parameters);

                    rsa.Dispose();
                }
                else
                {
                    key = new RsaSecurityKey(rsa);
                    parameters = key.Rsa?.ExportParameters(true) ?? key.Parameters;
                }
                key.KeyId = CryptoRandom.CreateUniqueId();

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

            });
        }
    }
}
