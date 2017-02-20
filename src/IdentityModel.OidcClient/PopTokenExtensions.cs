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

		/// <summary>
		/// Returns a new provider and JWK for signing pop tokens. Can be pre-called and passed to the login flow to diminish the visible time this is generating a key to users.
		/// </summary>
		/// <returns>The provider for pop token async.</returns>
		public static Task<RsaSecurityKey> CreateProviderForPopTokenAsync()
		{
			return Task.Run(() =>
			{
				var rsa = RSA.Create();
				if (rsa.KeySize < 2048)
				{
					rsa.Dispose();
					rsa = new RSACryptoServiceProvider(2048);
				}
				RsaSecurityKey key = null;
				if (rsa is RSACryptoServiceProvider)
				{
					key = new RsaSecurityKey(rsa);
				}
				else
				{
					key = new RsaSecurityKey(rsa);
				}
				key.Rsa.ExportParameters(false);
				key.KeyId = CryptoRandom.CreateUniqueId();
				return key;
			});
		}

		public static Jwk.JsonWebKey ToJwk(this RsaSecurityKey key)
		{
			var param = key.Rsa.ExportParameters(false);
			var exponent = Base64Url.Encode(param.Exponent);
			var modulus = Base64Url.Encode(param.Modulus);

			var webKey = new Jwk.JsonWebKey
			{
				Kty = "RSA",
				Alg = "RS256",
				Kid = key.KeyId,
				E = exponent,
				N = modulus,
			};

			return webKey;
		}
    }
}
