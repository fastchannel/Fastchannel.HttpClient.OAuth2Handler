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
        public double ExpiresInSeconds { private get; set; }

        [DataMember(Name = "scope")]
        public string Scope { get; set; }

        [DataMember(Name = "refresh_token_expires_in", EmitDefaultValue = false)]
        public double RefreshTokenExpiresInSeconds { private get; set; }

        [IgnoreDataMember]
        public TimeSpan ExpiresIn => TimeSpan.FromSeconds(ExpiresInSeconds);

        [IgnoreDataMember]
        public TimeSpan RefreshTokenExpiresIn => TimeSpan.FromSeconds(RefreshTokenExpiresInSeconds);

        [IgnoreDataMember]
        public DateTime IssueTimestamp { get; } = DateTime.UtcNow;

        public bool AccessTokenIsExpiredOrAboutToExpire() => DateTime.UtcNow >= IssueTimestamp.Add(ExpiresIn);

        public bool RefreshTokenIsExpiredOrAboutToExpire() => DateTime.UtcNow >= IssueTimestamp.Add(ExpiresIn);
    }
}
