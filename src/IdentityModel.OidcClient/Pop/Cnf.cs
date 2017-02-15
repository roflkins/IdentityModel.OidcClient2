using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;
using IdentityModel.Jwk;

namespace IdentityModel.OidcClient.Pop
{
    internal class Cnf
    {
        static JsonSerializerSettings _jsonSettings = new JsonSerializerSettings
        {
            NullValueHandling = NullValueHandling.Ignore
        };

        public Cnf(JsonWebKey jwk)
        {
            this.jwk = jwk;
        }

        public JsonWebKey jwk { get; set; }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this, _jsonSettings);
        }

    }
}
