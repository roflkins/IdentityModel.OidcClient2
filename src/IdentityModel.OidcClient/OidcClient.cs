﻿// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel.Client;
using System;
using System.Linq;
using System.Threading.Tasks;
using IdentityModel.OidcClient.Infrastructure;
using System.Security.Claims;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using IdentityModel.OidcClient.Results;
using IdentityModel.OidcClient.Browser;
using IdentityModel.Jwk;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using IdentityModel.OidcClient.Pop;

namespace IdentityModel.OidcClient
{
    /// <summary>
    /// OpenID Connect client
    /// </summary>
    public class OidcClient
    {
        private readonly OidcClientOptions _options;
        private readonly ILogger _logger;
        private readonly AuthorizeClient _authorizeClient;

        private readonly bool useDiscovery;
        private readonly ResponseProcessor _processor;

        public OidcClientOptions Options
        {
            get { return _options; }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OidcClient"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <exception cref="System.ArgumentNullException">options</exception>
        public OidcClient(OidcClientOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            if (options.ProviderInformation == null)
            {
                if (options.Authority.IsMissing()) throw new ArgumentException("No authority specified", nameof(_options.Authority));
                useDiscovery = true;
            }

            _options = options;
            _logger = options.LoggerFactory.CreateLogger<OidcClient>();
            _authorizeClient = new AuthorizeClient(options);
            _processor = new ResponseProcessor(options, EnsureProviderInformationAsync);
        }

        public async Task<LoginResult> LoginAsync(DisplayMode displayMode = DisplayMode.Visible, int timeout = 300, Task<Microsoft.IdentityModel.Tokens.RsaSecurityKey> pregeneratedPoPKeyTask = null, object extraParameters = null)
        {
            _logger.LogTrace("LoginAsync");
            _logger.LogInformation("Starting authentication request.");

            await EnsureConfigurationAsync().ConfigureAwait(false);
            var authorizeResult = await _authorizeClient.AuthorizeAsync(displayMode, timeout, pregeneratedPoPKeyTask, extraParameters).ConfigureAwait(false);

            if (authorizeResult.IsError)
            {
                return new LoginResult(authorizeResult.Error);
            }

            var result = await ProcessResponseAsync(authorizeResult.Data, authorizeResult.State).ConfigureAwait(false);

            if (!result.IsError)
            {
                _logger.LogInformation("Authentication request success.");
            }

            return result;
        }

        /// <summary>
        /// Prepares the login request.
        /// </summary>
        /// <param name="extraParameters">extra parameters to send to the authorize endpoint.</param>
        /// <returns>State for initiating the authorize request and processing the response</returns>
        public async Task<AuthorizeState> PrepareLoginAsync(Task<RsaSecurityKey> pregeneratedKeyTask = null, object extraParameters = null)
        {
            _logger.LogTrace("PrepareLoginAsync");

            await EnsureConfigurationAsync().ConfigureAwait(false);
            return _authorizeClient.CreateAuthorizeState(pregeneratedKeyTask, extraParameters);
        }

        /// <summary>
        /// Processes the authorize response.
        /// </summary>
        /// <param name="data">The response data.</param>
        /// <param name="state">The state.</param>
        /// <returns>Result of the login response validation</returns>
        public async Task<LoginResult> ProcessResponseAsync(string data, AuthorizeState state)
        {
            _logger.LogTrace("ProcessResponseAsync");
            _logger.LogInformation("Processing response.");

            _logger.LogDebug("Authorize response: {response}", data);
            var authorizeResponse = new AuthorizeResponse(data);

            if (authorizeResponse.IsError)
            {
                _logger.LogError(authorizeResponse.Error);
                return new LoginResult(authorizeResponse.Error);
            }

            var result = await _processor.ProcessResponseAsync(authorizeResponse, state).ConfigureAwait(false);
            if (result.IsError)
            {
                _logger.LogError(result.Error);
                return new LoginResult(result.Error);
            }

            var userInfoClaims = Enumerable.Empty<Claim>();
            if (_options.LoadProfile)
            {
                var userInfoResult = await GetUserInfoAsync(result.TokenResponse.AccessToken).ConfigureAwait(false);
                if (userInfoResult.IsError)
                {
                    var error = $"Error contacting userinfo endpoint: {userInfoResult.Error}";
                    _logger.LogError(error);

                    return new LoginResult(error);
                }

                userInfoClaims = userInfoResult.Claims;

                var userInfoSub = userInfoClaims.FirstOrDefault(c => c.Type == JwtClaimTypes.Subject);
                if (userInfoSub == null)
                {
                    var error = "sub claim is missing from userinfo endpoint";
                    _logger.LogError(error);

                    return new LoginResult(error);
                }

                if (!string.Equals(userInfoSub.Value, result.User.FindFirst(JwtClaimTypes.Subject).Value))
                {
                    var error = "sub claim from userinfo endpoint is different than sub claim from identity token.";
                    _logger.LogError(error);

                    return new LoginResult(error);
                }
            }

            var user = ProcessClaims(result.User, userInfoClaims);

			var loginResult = new LoginResult
			{
				User = user,
				AccessToken = result.TokenResponse.AccessToken,
				RefreshToken = result.TokenResponse.RefreshToken,
				AccessTokenExpiration = DateTime.Now.AddSeconds(result.TokenResponse.ExpiresIn),
				IdentityToken = result.TokenResponse.IdentityToken,
				AuthenticationTime = DateTime.Now,
				PopTokenKey = result.JwkProvider != null ? new SigningCredentials(result.JwkProvider, "RS256") : null
			};

            if (!string.IsNullOrWhiteSpace(loginResult.RefreshToken))
            {
                loginResult.RefreshTokenHandler = new RefreshTokenHandler(
                    TokenClientFactory.Create(_options),
                    loginResult.RefreshToken,
                    loginResult.AccessToken);
            }

            return loginResult;
        }

        /// <summary>
        /// Gets the user claims from the userinfo endpoint.
        /// </summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>User claims</returns>
        public async Task<UserInfoResult> GetUserInfoAsync(string accessToken)
        {
            _logger.LogTrace("GetUserInfoAsync");

            if (accessToken.IsMissing()) throw new ArgumentNullException(nameof(accessToken));
            if (!_options.ProviderInformation.SupportsUserInfo) throw new InvalidOperationException("No userinfo endpoint specified");

            var userInfoClient = new UserInfoClient(_options.ProviderInformation.UserInfoEndpoint, _options.BackchannelHandler);
            userInfoClient.Timeout = _options.BackchannelTimeout;

            var userInfoResponse = await userInfoClient.GetAsync(accessToken).ConfigureAwait(false);
            if (userInfoResponse.IsError)
            {
                return new UserInfoResult
                {
                    Error = userInfoResponse.Error
                };
            }

            return new UserInfoResult
            {
                Claims = userInfoResponse.Claims
            };
        }

        

        /// <summary>
        /// Refreshes an access token.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>A token response.</returns>
        public async Task<RefreshTokenResult> RefreshTokenAsync(string refreshToken, Task<RsaSecurityKey> pregeneratedPopKeyTask = null)
        {
			if (string.IsNullOrEmpty(refreshToken)) throw new ArgumentException("refreshToken");
            _logger.LogTrace("RefreshTokenAsync");

			await EnsureConfigurationAsync().ConfigureAwait(false);

            var client = TokenClientFactory.Create(_options);


			TokenResponse response;
			SigningCredentials popSigner = null;

			if (_options.RequestPopTokens)
			{
				//-- PoP Key Creation
				_logger.LogTrace("CreateProviderForPopToken");
				var popKey = await (pregeneratedPopKeyTask ?? PopTokenExtensions.CreateProviderForPopTokenAsync()).ConfigureAwait(false);
				var jwk = popKey.ToJwk();
				response = await client.RequestRefreshTokenPopAsync(refreshToken, jwk.Alg, jwk.ToJwkString()).ConfigureAwait(false);
				popSigner = new SigningCredentials(popKey, "RS256");
			}
			else
				response = await client.RequestRefreshTokenAsync(refreshToken).ConfigureAwait(false);

            if (response.IsError)
            {
                return new RefreshTokenResult { Error = response.Error };
            }

            // validate token response
            var validationResult = await _processor.ValidateTokenResponseAsync(response, null, requireIdentityToken: _options.Policy.RequireIdentityTokenOnRefreshTokenResponse).ConfigureAwait(false);
            if (validationResult.IsError)
            {
                return new RefreshTokenResult { Error = validationResult.Error };
            }

            return new RefreshTokenResult
            {
                IdentityToken = response.IdentityToken,
                AccessToken = response.AccessToken,
                RefreshToken = response.RefreshToken,
                ExpiresIn = (int)response.ExpiresIn,
                PopTokenKey = popSigner
            };
        }

		/// <summary>
		/// Pre preforms the discovery mechanism.
		/// </summary>
		/// <returns>The discovery async.</returns>
		public async Task PreformDiscoveryAsync()
		{
			await EnsureConfigurationAsync().ConfigureAwait(false);
		}

        internal async Task EnsureConfigurationAsync()
        {
            if (_options.Flow == OidcClientOptions.AuthenticationFlow.Hybrid && _options.Policy.RequireIdentityTokenSignature == false)
            {
                var error = "Allowing unsigned identity tokens is not allowed for hybrid flow";
                _logger.LogError(error);

                throw new InvalidOperationException(error);
            }

            await EnsureProviderInformationAsync().ConfigureAwait(false);

            _logger.LogDebug("Effective options:");
            _logger.LogDebug(LogSerializer.Serialize(_options));
        }

        internal async Task EnsureProviderInformationAsync()
        {
            _logger.LogTrace("EnsureProviderInformation");

            if (useDiscovery)
            {
                if (_options.RefreshDiscoveryDocumentForLogin == false)
                {
                    // discovery document has been loaded before - skip reload
                    if (_options.ProviderInformation != null)
                    {
                        _logger.LogDebug("Skipping refresh of discovery document.");

                        return;
                    }
                }

                var client = new DiscoveryClient(_options.Authority, _options.BackchannelHandler)
                {
                    Policy = _options.Policy.Discovery,
                    Timeout = _options.BackchannelTimeout
                };

                var disco = await client.GetAsync().ConfigureAwait(false);
                
                if (disco.IsError)
                {
                    _logger.LogError("Error loading discovery document: {errorType} - {error}", disco.ErrorType.ToString(), disco.Error);

                    throw new InvalidOperationException("Error loading discovery document: " + disco.Error);
                }

                _logger.LogDebug("Successfully loaded discovery document");
                _logger.LogDebug("Loaded keyset from {jwks_uri}", disco.JwksUri);
                _logger.LogDebug("Keyet contains the following kids: {kids}", from k in disco.KeySet.Keys select k.Kid ?? "unspecified");

                _options.ProviderInformation = new ProviderInformation
                {
                    IssuerName = disco.Issuer,
                    KeySet = disco.KeySet,

                    AuthorizeEndpoint = disco.AuthorizeEndpoint,
                    TokenEndpoint = disco.TokenEndpoint,
                    EndSessionEndpoint = disco.EndSessionEndpoint,
                    UserInfoEndpoint = disco.UserInfoEndpoint,
                    TokenEndPointAuthenticationMethods = disco.TokenEndpointAuthenticationMethodsSupported
                };
            }

            if (_options.ProviderInformation.IssuerName.IsMissing())
            {
                var error = "Issuer name is missing in provider information";

                _logger.LogError(error);
                throw new InvalidOperationException(error);
            }

            if (_options.ProviderInformation.AuthorizeEndpoint.IsMissing())
            {
                var error = "Authorize endpoint is missing in provider information";

                _logger.LogError(error);
                throw new InvalidOperationException(error);
            }

            if (_options.ProviderInformation.TokenEndpoint.IsMissing())
            {
                var error = "Token endpoint is missing in provider information";

                _logger.LogError(error);
                throw new InvalidOperationException(error);
            }

            if (_options.ProviderInformation.KeySet == null)
            {
                var error = "Key set is missing in provider information";

                _logger.LogError(error);
                throw new InvalidOperationException(error);
            }
        }

        internal ClaimsPrincipal ProcessClaims(ClaimsPrincipal user, IEnumerable<Claim> userInfoClaims)
        {
            _logger.LogTrace("ProcessClaims");

            var combinedClaims = new HashSet<Claim>(new ClaimComparer(compareValueAndTypeOnly: true));

            user.Claims.ToList().ForEach(c => combinedClaims.Add(c));
            userInfoClaims.ToList().ForEach(c => combinedClaims.Add(c));

            var userClaims = new List<Claim>();
            if (_options.FilterClaims)
            {
                userClaims = combinedClaims.Where(c => !_options.FilteredClaims.Contains(c.Type)).ToList();
            }
            else
            {
                userClaims = combinedClaims.ToList();
            }

            return new ClaimsPrincipal(new ClaimsIdentity(userClaims, user.Identity.AuthenticationType, user.Identities.First().NameClaimType, user.Identities.First().RoleClaimType));
        }

        /// <summary>
        /// Creates a pop/HMAC token using the payload and signature key specified.
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public JwtSecurityToken CreatePopToken(JwtPayload payload, SigningCredentials signer)
        {
            if (payload == null) throw new ArgumentNullException("payload");
            if (signer == null) throw new ArgumentNullException("signer");
            var jHeader = new JwtHeader(signer);
            jHeader.Remove("kid"); //Other implementations seem to omit this - and it maybe best since either introspection or the access token will have the key used to validate.
            var jwt = new JwtSecurityToken(jHeader, payload);
            return jwt;
        }
        
        /// <summary>
        /// Checks the PoP/HMAC token for validity by verifiying both the access token signature (if JWT) and validity (if using or requiring introspection), as well as the hmac and timestamp. 
        /// *Does not* validate nonce or the expected parameters in the body of the token.
        /// </summary>
        /// <param name="token"></param>
        /// <param name="scope"></param>
        /// <param name="scopeSecret"></param>
        /// <returns></returns>
        public  async Task<AccessTokenValidationResult> ValidatePopToken(string token, bool forceIntrospection = false, string scope = null, string scopeSecret = null)
        {
            if (string.IsNullOrEmpty(token)) throw new ArgumentNullException("popToken");
            if (string.IsNullOrEmpty(scope)) throw new ArgumentNullException("scope");
            if (string.IsNullOrEmpty(scopeSecret)) throw new ArgumentNullException("scopeSecret");

            await EnsureConfigurationAsync().ConfigureAwait(false);

            var processor = new PopAccessTokenValidator(_options, EnsureProviderInformationAsync);
            return await processor.ValidateAsync(token, forceIntrospection, scope, scopeSecret).ConfigureAwait(false);

        }

        /// <summary>
        /// Validates a bearer access token for validity by verifiying both the access token signature (if JWT) and validity (if using or requiring introspection).
        /// </summary>
        /// <param name="token"></param>
        /// <param name="scope"></param>
        /// <param name="scopeSecret"></param>
        /// <returns></returns>
        public async Task<Results.AccessTokenValidationResult> ValidateToken(string token, bool forceIntrospection = false, string scope = null, string scopeSecret = null)
        {
            if (string.IsNullOrEmpty(token)) throw new ArgumentNullException("popToken");
            if (string.IsNullOrEmpty(scope)) throw new ArgumentNullException("scope");
            if (string.IsNullOrEmpty(scopeSecret)) throw new ArgumentNullException("scopeSecret");

            await EnsureConfigurationAsync().ConfigureAwait(false);

            var processor = new AccessTokenValidator(_options, EnsureProviderInformationAsync);
            return await processor.ValidateAsync(token, forceIntrospection, scope, scopeSecret).ConfigureAwait(false);

        }
    }
}