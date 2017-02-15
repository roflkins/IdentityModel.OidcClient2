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
        
    }
}
