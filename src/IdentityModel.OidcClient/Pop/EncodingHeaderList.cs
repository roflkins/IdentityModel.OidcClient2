using System.Collections.Generic;

namespace IdentityModel.OidcClient.Pop
{
    public class EncodingHeaderList : EncodingList
    {
        public EncodingHeaderList(OidcClientOptions options, ICollection<KeyValuePair<string, string>> list)
            : base(options, list, HttpSigningConstants.HashedRequestHeaderSeparators.KeyValueSeparator, HttpSigningConstants.HashedRequestHeaderSeparators.ParameterSeparator, true)
        {
        }
    }
}