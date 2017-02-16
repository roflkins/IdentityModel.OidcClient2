// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace IdentityModel.OidcClient.Results
{
    public class AccessTokenValidationResult : Result
    {
        public ClaimsPrincipal AccessTokenPrincipal { get; set; }
        public ClaimsPrincipal PopTokenPrincipal { get; set; }
        public string AccessTokenSignatureAlgorithm { get; set; }
        public string PopTokenSignatureAlgorithm { get; set; }
        public bool ValidatedByIntrospection { get; set; }
        public bool PreformedPopTokenValidation { get; set; }
    }
}