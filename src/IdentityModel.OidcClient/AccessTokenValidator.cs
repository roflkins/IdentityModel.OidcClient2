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
    internal class AccessTokenValidator
    {
        private readonly ILogger _logger;
        private readonly OidcClientOptions _options;
        private readonly Func<Task> _refreshKeysAsync;

        public AccessTokenValidator(OidcClientOptions options, Func<Task> refreshKeysAsync)
        {
            _options = options;
            _logger = options.LoggerFactory.CreateLogger<AccessTokenValidator>();
            _refreshKeysAsync = refreshKeysAsync;
        }

        /// <summary>
        /// Validates the specified identity token.
        /// </summary>
        /// <param name="identityToken">The identity token.</param>
        /// <returns>The validation result</returns>
        public async Task<AccessTokenValidationResult> ValidateAsync(string accessToken, string introspectionScope, string introspectionSecret)
        {
            _logger.LogTrace("Validate");

            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();

            // setup general validation parameters
            var parameters = new TokenValidationParameters
            {
                ValidIssuer = _options.ProviderInformation.IssuerName,
                ValidAudience = string.Format("{0}/resources", _options.Authority)
            };

            // read the token signing algorithm
            JwtSecurityToken jwt;

            try
            {
                jwt = handler.ReadJwtToken(accessToken);
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
                        Error = $"Identity token is not singed. Signatures are required by policy"
                    };
                }
                else
                {
                    _logger.LogInformation("Identity token is not signed. This is allowed by configuration.");
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
                        Error = $"Identity token uses invalid algorithm: {algorithm}"
                    };
                };
            }


            ClaimsPrincipal claims;
            try
            {
                claims = ValidateSignature(accessToken, handler, parameters);
            }
            catch (SecurityTokenSignatureKeyNotFoundException sigEx)
            {
                if (_options.RefreshDiscoveryOnSignatureFailure)
                {
                    _logger.LogWarning("Key for validating token signature cannot be found. Refreshing keyset.");

                    // try to refresh the key set and try again
                    await _refreshKeysAsync();

                    try
                    {
                        claims = ValidateSignature(accessToken, handler, parameters);
                    }
                    catch (Exception ex)
                    {
                        return new AccessTokenValidationResult
                        {
                            Error = $"Error validating access token: {ex.ToString()}"
                        };
                    }
                }
                else
                {
                    return new AccessTokenValidationResult
                    {
                        Error = $"Error validating access token: {sigEx.ToString()}"
                    };
                }
            }
            catch (Exception ex)
            {
                return new AccessTokenValidationResult
                {
                    Error = $"Error validating access token: {ex.ToString()}"
                };
            }

            return new AccessTokenValidationResult()
            {
                ClaimsPrincipal = claims,
                SignatureAlgorithm = algorithm
            };
        }

        private ClaimsPrincipal ValidateSignature(string accessToken, JwtSecurityTokenHandler handler, TokenValidationParameters parameters)
        {
            if (parameters.RequireSignedTokens)
            {
                // read keys from provider information
                var keys = new List<SecurityKey>();

                foreach (var webKey in _options.ProviderInformation.KeySet.Keys)
                {
                    // todo: only supports RSA keys right now
                    if (webKey.E.IsPresent() && webKey.N.IsPresent())
                    {
                        // only add keys used for signatures
                        if (webKey.Use == "sig")
                        {
                            var e = Base64Url.Decode(webKey.E);
                            var n = Base64Url.Decode(webKey.N);

                            var key = new RsaSecurityKey(new RSAParameters { Exponent = e, Modulus = n });
                            key.KeyId = webKey.Kid;

                            keys.Add(key);

                            _logger.LogDebug("Added signing key with kid: {kid}", key?.KeyId ?? "not set");
                        }
                    }
                    else
                    {
                        _logger.LogDebug("Signing key with kid: {kid} currently not supported", webKey.Kid ?? "not set");
                    }
                }

                parameters.IssuerSigningKeys = keys;
            }

            SecurityToken token;
            return handler.ValidateToken(accessToken, parameters, out token);
        }

       
    }
}