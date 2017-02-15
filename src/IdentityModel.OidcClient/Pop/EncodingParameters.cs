using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Http;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Linq;

namespace IdentityModel.OidcClient.Pop
{
    public class EncodingParameters
    {
        private readonly ILogger<EncodingParameters> Logger = null;

        private OidcClientOptions _options = null;

        public EncodingParameters(OidcClientOptions options, string accessToken)
        { 
            if (String.IsNullOrWhiteSpace(accessToken))
            {
                throw new ArgumentNullException("accessToken");
            }

            AccessToken = accessToken;
            TimeStamp = DateTimeOffset.UtcNow;
            QueryParameters = new List<KeyValuePair<string, string>>();
            RequestHeaders = new List<KeyValuePair<string, string>>();
            Logger = options.LoggerFactory.CreateLogger<EncodingParameters>();

            this._options = options;
        }

        public string AccessToken { get; private set; }
        public DateTimeOffset TimeStamp { get; set; }
        public string Method { get; set; }
        public string Host { get; set; }
        public string Path { get; set; }
        public IList<KeyValuePair<string, string>> QueryParameters { get; set; }
        public IList<KeyValuePair<string, string>> RequestHeaders { get; set; }
        public byte[] Body { get; set; }

        public EncodedParameters Encode()
        {
            var result = new EncodedParameters(_options, AccessToken);
            result.TimeStamp = TimeStamp.ToEpochTime();

            if (Method != null)
            {
                Logger.LogDebug("Encoding method");
                result.Method = Method;
            }

            if (Host != null)
            {
                Logger.LogDebug("Encoding host");
                result.Host = Host;
            }

            if (Path != null)
            {
                Logger.LogDebug("Encoding path");
                result.Path = Path;
            }

            if (QueryParameters != null && QueryParameters.Any())
            {
                Logger.LogDebug("Encoding query params");
                var query = new EncodingQueryParameters(_options, QueryParameters);
                result.QueryParameters = query.Encode();
            }

            if (RequestHeaders != null && RequestHeaders.Any())
            {
                Logger.LogDebug("Encoding request headers");
                var headers = new EncodingHeaderList(_options, RequestHeaders);
                result.RequestHeaders = headers.Encode();
            }

            if (Body != null)
            {
                Logger.LogDebug("Encoding body");
                result.BodyHash = CalculateBodyHash();
            }

            return result;
        }

        string CalculateBodyHash()
        {
            var hash = SHA256.Create().ComputeHash(Body);
            return IdentityModel.Base64Url.Encode(hash);
        }
    }
}
