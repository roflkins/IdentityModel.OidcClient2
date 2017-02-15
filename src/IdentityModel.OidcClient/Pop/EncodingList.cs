using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;

namespace IdentityModel.OidcClient.Pop
{
    public class EncodingList
    {
        private readonly ILogger<EncodingList> Logger = null;

        private OidcClientOptions _options = null;

        public EncodingList(
            OidcClientOptions options,
            ICollection<KeyValuePair<string, string>> list,
            string keyValueSeparator,
            string parameterSeparator,
            bool lowerCaseKeys)
        {
            if (list == null) throw new ArgumentNullException("list");
            if (list.Any() == false) throw new ArgumentException("list is empty");
            if (keyValueSeparator == null) throw new ArgumentNullException("keyValueSeparator");
            if (parameterSeparator == null) throw new ArgumentNullException("parameterSeparator");
            Logger = options.LoggerFactory.CreateLogger<EncodingList>();
            _options = options;
            Encode(list, keyValueSeparator, parameterSeparator, lowerCaseKeys);
        }

        void Encode(
            ICollection<KeyValuePair<string, string>> list,
            string keyValueSeparator,
            string parameterSeparator,
            bool lowerCaseKeys)
        {
            var keys = new List<string>();
            var values = new StringBuilder();

            foreach (var item in list)
            {
                var key = item.Key;
                if (lowerCaseKeys)
                {
                    key = key.ToLowerInvariant();
                }
                var value = item.Value;

                keys.Add(key);
                if (values.Length > 0)
                {
                    values.Append(parameterSeparator);
                }

                values.Append(key);
                values.Append(keyValueSeparator);
                values.Append(value);

                Logger.LogDebug("Encoding key: {0}", key);
            }

            Keys = keys;
            Value = values.ToString();
        }

        public IEnumerable<string> Keys { get; private set; }
        public string Value { get; private set; }

        public EncodedList Encode()
        {
            var bytes = Encoding.ASCII.GetBytes(Value);
            var hash = SHA256.Create().ComputeHash(bytes);
            var value = Base64Url.Encode(hash);

            return new EncodedList(_options, Keys, value);
        }
    }
}
