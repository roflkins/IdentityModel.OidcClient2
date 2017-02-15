using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Security.Cryptography;
using IdentityModel.OidcClient.Pop;

namespace IdentityModel.OidcClient
{
    public static class PopTokenService
    {
        public static JwtSecurityToken GeneratePopToken(EncodingParameters parameters, RsaSecurityKey key)
        {
            if (parameters == null) throw new ArgumentNullException("parameters");
            if (key == null) throw new ArgumentNullException("key");
            var payload = parameters.Encode();
            var encoded = payload.Encode();
            var jPayload = new JwtPayload();
            foreach (var values in encoded)
                jPayload.Add(values.Key, values.Value);
            var jHeader = new JwtHeader(new SigningCredentials(key, "RS256"));
            jHeader.Remove("kid");
            var jwt = new JwtSecurityToken(jHeader, jPayload);
            return jwt;
        }

        public static string ToPopTokenString(this JwtSecurityToken token)
        {
            var handler = new JwtSecurityTokenHandler();
            handler.OutboundClaimTypeMap.Clear();

            return handler.WriteToken(token);
        }

        public static async Task<Results.AccessTokenValidationResult> ValidatePopToken(OidcClientOptions options, OidcClient client, string token, string scope, string scopeSecret)
        {
            if (string.IsNullOrEmpty(token)) throw new ArgumentNullException("popToken");
            if (string.IsNullOrEmpty(scope)) throw new ArgumentNullException("scope");
            if (string.IsNullOrEmpty(scopeSecret)) throw new ArgumentNullException("scopeSecret");
            var processor = new PopAccessTokenValidator(options, client.EnsureProviderInformationAsync);
            return await processor.ValidateAsync(token, scope, scopeSecret);
            
        }

        public static async Task<Results.AccessTokenValidationResult> ValidateToken(OidcClientOptions options, OidcClient client, string token, string scope, string scopeSecret)
        {
            if (string.IsNullOrEmpty(token)) throw new ArgumentNullException("popToken");
            if (string.IsNullOrEmpty(scope)) throw new ArgumentNullException("scope");
            if (string.IsNullOrEmpty(scopeSecret)) throw new ArgumentNullException("scopeSecret");
            var processor = new AccessTokenValidator(options, client.EnsureProviderInformationAsync);
            return await processor.ValidateAsync(token, scope, scopeSecret);

        }
    }
}
