// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace IdentityModel.OidcClient.Results
{
    public class AccessTokenValidationResult : Result
    {
        public ClaimsPrincipal ClaimsPrincipal { get; set; }
        public string SignatureAlgorithm { get; set; }
      
    }
}