using System.Collections.Generic;

namespace IdentityModel.OidcClient.Pop
{
    public class EncodingQueryParameters : EncodingList
    {
        public EncodingQueryParameters(OidcClientOptions options, ICollection<KeyValuePair<string, string>> list)
            : base( options, list, HttpSigningConstants.HashedQuerySeparators.KeyValueSeparator, HttpSigningConstants.HashedQuerySeparators.ParameterSeparator, false)
        {
        }
    }
}