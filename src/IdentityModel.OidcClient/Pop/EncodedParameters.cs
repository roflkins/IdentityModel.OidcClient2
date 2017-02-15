using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;
using Microsoft.Extensions.Logging;

namespace IdentityModel.OidcClient.Pop
{
    public class EncodedParameters
    {
        private readonly OidcClientOptions _options;
        private readonly ILogger<EncodedParameters> Logger = null;

        public EncodedParameters(OidcClientOptions options, string accessToken)
        {
            if (String.IsNullOrWhiteSpace(accessToken))
            {
                throw new ArgumentNullException("accessToken");
            }

            Logger = options.LoggerFactory.CreateLogger<EncodedParameters>();
            this._options = options;

            AccessToken = accessToken;
        }

        public EncodedParameters(OidcClientOptions options, IDictionary<string, object> values)
        {
            if (values == null) throw new ArgumentNullException("values");

            Decode(values);
            Logger = options.LoggerFactory.CreateLogger<EncodedParameters>();
            this._options = options;
        }

        static JsonSerializerSettings _jsonSettings = new JsonSerializerSettings()
        {
            NullValueHandling = NullValueHandling.Ignore
        };

        public static EncodedParameters FromJson(OidcClientOptions options, string json)
        {
            if (String.IsNullOrWhiteSpace(json))
            {
                //Logger.LogError("No JSON");
                return null;
            }

            Dictionary<string, object> values = null;
            try
            {
                values = JsonConvert.DeserializeObject<Dictionary<string, object>>(json, _jsonSettings);
                return new EncodedParameters(options, values);
            }
            catch (Exception ex)
            {
                //Logger.LogError("Failed to deserialize JSON {0}", ex);
            }

            return null;
        }

        public string AccessToken { get; private set; }
        public long? TimeStamp { get; set; }
        public string Method { get; set; }
        public string Host { get; set; }
        public string Path { get; set; }
        public EncodedList QueryParameters { get; set; }
        public EncodedList RequestHeaders { get; set; }
        public string BodyHash { get; set; }

        public bool IsSame(EncodedParameters other)
        {
            if (other == null) return false;

            if (AccessToken != other.AccessToken)
            {
                Logger.LogDebug("AccessToken mismatch");
                return false;
            }
            if (Method != other.Method)
            {
                Logger.LogDebug("Method mismatch");
                return false;
            }
            if (Host != other.Host)
            {
                Logger.LogDebug("Host mismatch");
                return false;
            }
            if (Path != other.Path)
            {
                Logger.LogDebug("Path mismatch");
                return false;
            }
            if (BodyHash != other.BodyHash)
            {
                Logger.LogDebug("BodyHash mismatch");
                return false;
            }

            if (QueryParameters == null && other.QueryParameters != null)
            {
                Logger.LogDebug("One QueryParameters is null, the other is not");
                return false;
            }
            if (QueryParameters != null && other.QueryParameters == null)
            {
                Logger.LogDebug("One QueryParameters is null, the other is not");
                return false;
            }
            if (QueryParameters != null && !QueryParameters.IsSame(other.QueryParameters))
            {
                Logger.LogDebug("QueryParameters mismatch");
                return false;
            }

            if (RequestHeaders == null && other.RequestHeaders != null)
            {
                Logger.LogDebug("One RequestHeaders is null, the other is not");
                return false;
            }
            if (RequestHeaders != null && other.RequestHeaders == null)
            {
                Logger.LogDebug("One RequestHeaders is null, the other is not");
                return false;
            }
            if (RequestHeaders != null && !RequestHeaders.IsSame(other.RequestHeaders))
            {
                Logger.LogDebug("RequestHeaders mismatch");
                return false;
            }

            return true;
        }

        public Dictionary<string, object> Encode()
        {
            var value = new Dictionary<string, object>();
            
            value.Add(HttpSigningConstants.SignedObjectParameterNames.AccessToken, AccessToken);

            if (TimeStamp != null)
            {
                Logger.LogDebug("Encoding timestamp");
                value.Add(HttpSigningConstants.SignedObjectParameterNames.TimeStamp, TimeStamp.Value);
            }

            if (Method != null)
            {
                Logger.LogDebug("Encoding method");
                value.Add(HttpSigningConstants.SignedObjectParameterNames.Method, Method);
            }

            if (Host != null)
            {
                Logger.LogDebug("Encoding host");
                value.Add(HttpSigningConstants.SignedObjectParameterNames.Host, Host);
            }

            if (Path != null)
            {
                Logger.LogDebug("Encoding path");
                value.Add(HttpSigningConstants.SignedObjectParameterNames.Path, Path);
            }

            if (QueryParameters != null)
            {
                Logger.LogDebug("Encoding query params");
                value.Add(HttpSigningConstants.SignedObjectParameterNames.HashedQueryParameters, JsonConvert.SerializeObject(QueryParameters.Encode()));
            }

            if (RequestHeaders != null)
            {
                Logger.LogDebug("Encoding request headers");
                value.Add(HttpSigningConstants.SignedObjectParameterNames.HashedRequestHeaders, JsonConvert.SerializeObject(RequestHeaders.Encode()));
            }

            if (BodyHash != null)
            {
                Logger.LogDebug("Encoding body hash");
                value.Add(HttpSigningConstants.SignedObjectParameterNames.HashedRequestBody, BodyHash);
            }

            return value;
        }

        private void Decode(IDictionary<string, object> values)
        {
            AccessToken = GetString(values, HttpSigningConstants.SignedObjectParameterNames.AccessToken);
            if (AccessToken == null)
            {
                Logger.LogError(HttpSigningConstants.SignedObjectParameterNames.AccessToken + " value not present");
                throw new ArgumentException(HttpSigningConstants.SignedObjectParameterNames.AccessToken + " value not present");
            }

            var ts = GetNumber(values, HttpSigningConstants.SignedObjectParameterNames.TimeStamp);
            if (ts != null)
            {
                Logger.LogDebug("Decoded Timestamp");
                TimeStamp = ts;
            }

            Method = GetString(values, HttpSigningConstants.SignedObjectParameterNames.Method);
            if (Method != null) Logger.LogDebug("Decoded Method");

            Host = GetString(values, HttpSigningConstants.SignedObjectParameterNames.Host);
            if (Host != null) Logger.LogDebug("Decoded Host");

            Path = GetString(values, HttpSigningConstants.SignedObjectParameterNames.Path);
            if (Path != null) Logger.LogDebug("Decoded Path");

            QueryParameters = GetDecodedList(values, HttpSigningConstants.SignedObjectParameterNames.HashedQueryParameters);
            if (QueryParameters != null) Logger.LogDebug("Decoded QueryParameters");

            RequestHeaders = GetDecodedList(values, HttpSigningConstants.SignedObjectParameterNames.HashedRequestHeaders);
            if (RequestHeaders != null) Logger.LogDebug("Decoded RequestHeaders");

            BodyHash = GetString(values, HttpSigningConstants.SignedObjectParameterNames.HashedRequestBody);
            if (BodyHash != null) Logger.LogDebug("Decoded BodyHash");
        }

        EncodedList GetDecodedList(IDictionary<string, object> values, string key)
        {
            if (values.ContainsKey(key))
            { 
                var item = values[key];
                return new EncodedList(item);
            }
            return null;
        }

        string GetString(IDictionary<string, object> values, string key)
        {
            if (values.ContainsKey(key))
            {
                var item = values[key] as string;
                if (item == null)
                {
                    Logger.LogError(key + " must be a string");
                    throw new ArgumentException(key + " must be a string");
                }
                return item;
            }
            return null;
        }

        long? GetNumber(IDictionary<string, object> values, string key)
        {
            if (values.ContainsKey(key))
            {
                var item = values[key];
                var type = item.GetType();

                if (typeof(long) == type)
                {
                    return (long)item;
                }

                if (typeof(int) == type)
                {
                    return (int)item;
                }

                if (typeof(short) == type)
                {
                    return (short)item;
                }

                Logger.LogError(key + " must be a number");
                throw new ArgumentException(key + " must be a number");
            }
            return null;
        }
    }
}
