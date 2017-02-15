using IdentityModel.Client;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace IdentityModel.OidcClient
{
    public class ResponseValidationResult : Result
    {
        public ResponseValidationResult()
        {

        }

        public ResponseValidationResult(string error)
        {
            Error = error;
        }

        public AuthorizeResponse AuthorizeResponse { get; set; }
        public TokenResponse TokenResponse { get; set; }
        public ClaimsPrincipal User { get; set; }
        public RsaSecurityKey JwkProvider { get; set; }
    }
}