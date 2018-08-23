using System;
using System.Runtime.Serialization;

namespace Kaive.HttpClient.OAuth2Handler.Authorizer
{
    [DataContract]
    public class TokenResponse
    {
        [DataMember(Name = "access_token")]
        public string AccessToken { get; set; }

        [DataMember(Name = "refresh_token")]
        public string RefreshToken { get; set; }

        [DataMember(Name = "token_type")]
        public string TokenType { get; set; }

        [DataMember(Name = "expires_in")]
        public int ExpiresInSeconds { private get; set; }

        public TimeSpan ExpiresIn => TimeSpan.FromSeconds(ExpiresInSeconds);
    }
}
