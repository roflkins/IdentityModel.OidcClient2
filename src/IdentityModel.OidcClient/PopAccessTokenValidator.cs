using IdentityModel.OidcClient.Results;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using IdentityModel.Client;
using System.Linq;
using IdentityModel.OidcClient.Pop;

namespace IdentityModel.OidcClient
{
    internal class PopAccessTokenValidator
    {
        private readonly ILogger _logger;
        private readonly OidcClientOptions _options;
        private readonly Func<Task> _refreshKeysAsync;

        public PopAccessTokenValidator(OidcClientOptions options, Func<Task> refreshKeysAsync)
        {
            _options = options;
            _logger = options.LoggerFactory.CreateLogger<PopAccessTokenValidator>();
            _refreshKeysAsync = refreshKeysAsync;
        }

        /// <summary>
        /// Validates the specified identity token.
        /// </summary>
        /// <param name="identityToken">The identity token.</param>
        /// <returns>The validation result</returns>
        public async Task<AccessTokenValidationResult> ValidateAsync(string popToken, bool forceIntrospection = false, string introspectionScope = null, string introspectionSecret = null)
        {
            _logger.LogTrace("Validate PoP Token");

            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();

            // setup general validation parameters
            var parameters = new TokenValidationParameters
            {
                ValidIssuer = _options.ProviderInformation.IssuerName,
                ValidateAudience = false, //Pop tokens don't have this - they use the body data.
                RequireExpirationTime = false,
                ValidateIssuer = false
            };

            // read the token signing algorithm
            JwtSecurityToken jwt;

            try
            {
                jwt = handler.ReadJwtToken(popToken);
            }
            catch (Exception ex)
            {
                return new AccessTokenValidationResult
                {
                    Error = $"Error validating access token: {ex.ToString()}"
                };
            }

            var algorithm = jwt.Header.Alg;

            // if token is unsigned, and this is allowed, skip signature validation
            if (string.Equals(algorithm, "none"))
            {
                if (_options.Policy.RequireAccessTokenSignature)
                {
                    return new AccessTokenValidationResult
                    {
                        Error = $"Pop access token is not singed. Signatures are required by policy"
                    };
                }
                else
                {
                    _logger.LogInformation("Pop token is not signed. This is allowed by configuration.");
                    parameters.RequireSignedTokens = false;
                }
            }
            else
            {
                // check if signature algorithm is allowed by policy
                if (!_options.Policy.ValidSignatureAlgorithms.Contains(algorithm))
                {
                    return new AccessTokenValidationResult
                    {
                        Error = $"Pop token uses invalid algorithm: {algorithm}"
                    };
                };
            }

            var extractedAccessToken = jwt.Payload.ContainsKey("at") ? jwt.Payload["at"] as string : null;
            if (string.IsNullOrEmpty(extractedAccessToken))
            {
                _logger.LogInformation("Pop token was recieved without 'at'");
                return new AccessTokenValidationResult
                {
                    Error = "Token is invalid."
                };
            }

            //Attempt to validate the JWT, if possible.
            AccessTokenValidationResult tokenValidation = null;
            try
            {
               tokenValidation = await new AccessTokenValidator(_options, _refreshKeysAsync).ValidateAsync(extractedAccessToken, forceIntrospection, introspectionScope, introspectionSecret).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                return new AccessTokenValidationResult
                {
                    Error = $"Error validating pop access token: {ex.ToString()}"
                };
            }

            if (tokenValidation.IsError) //If we failed - pass it through.
                return tokenValidation;

            //Get the signature keys and preform online validation.
            var cnfJson = tokenValidation.AccessTokenPrincipal.Claims.FirstOrDefault(x => x.Type == "cnf")?.Value;
            if (cnfJson == null)
            {
                _logger.LogError("CNF is not present on the AccessTokenPrincipal");
                return new AccessTokenValidationResult() { Error = "Token validation failed." };
            }

            Cnf cnf = Newtonsoft.Json.JsonConvert.DeserializeObject<Cnf>(cnfJson);
           
            ClaimsPrincipal claims;
            try
            {
                claims = ValidateSignature(popToken,cnf.jwk, handler, parameters);
            }
            catch (SecurityTokenSignatureKeyNotFoundException sigEx)
            {
                return new AccessTokenValidationResult
                {
                    Error = $"Error validating pop access token: {sigEx.ToString()}"
                };
            }
            catch (Exception ex)
            {
                return new AccessTokenValidationResult
                {
                    Error = $"Error validating pop access token: {ex.ToString()}"
                };
            }

            tokenValidation.PopTokenPrincipal = claims;
            tokenValidation.PopTokenSignatureAlgorithm = algorithm;
            tokenValidation.PreformedPopTokenValidation = true;
            return tokenValidation;
        }

        private ClaimsPrincipal ValidateSignature(string accessToken, IdentityModel.Jwk.JsonWebKey cnf, JwtSecurityTokenHandler handler, TokenValidationParameters parameters)
        {
            if (parameters.RequireSignedTokens)
            {
                // read keys from provider information
                var keys = new List<SecurityKey>();

                // todo: only supports RSA keys right now
                if (cnf.E.IsPresent() && cnf.N.IsPresent())
                {
                        var e = Base64Url.Decode(cnf.E);
                        var n = Base64Url.Decode(cnf.N);

                        var key = new RsaSecurityKey(new RSAParameters { Exponent = e, Modulus = n });
                        key.KeyId = cnf.Kid;

                        keys.Add(key);

                        _logger.LogDebug("Added signing key with kid: {kid}", key?.KeyId ?? "not set");
                }
                else
                {
                    _logger.LogDebug("Signing key with kid: {kid} currently not supported", cnf.Kid ?? "not set");
                }

                parameters.IssuerSigningKeys = keys;
            }

            SecurityToken token;
            return handler.ValidateToken(accessToken, parameters, out token);
        }

       
    }
}