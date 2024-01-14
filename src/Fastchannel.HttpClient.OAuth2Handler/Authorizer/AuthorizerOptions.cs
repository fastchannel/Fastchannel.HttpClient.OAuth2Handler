using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;

namespace Fastchannel.HttpClient.OAuth2Handler.Authorizer
{
    public class AuthorizerOptions
    {
        public Uri TokenEndpointUri { get; set; }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public string Username { get; set; }

        public string Password { get; set; }

        public string Resource { get; set; }

        public IEnumerable<string> Scope { get; set; }

        public bool SetGrantTypeOnQueryString { get; set; }

        public GrantType GrantType { get; set; }

        public CredentialsTransportMethod CredentialsTransportMethod { get; set; }

        public TokenRequestContentType TokenRequestContentType { get; set; }

        public Dictionary<string, string> CredentialsKeyNames { get; set; }

        public AccessTokenResponseOptions AccessTokenResponseOptions { get; set; }

        public Action<HttpStatusCode, string> OnError { get; set; }

        public Action<HttpRequestMessage, string> OnTokenRefresh { get; set; }

        public AuthorizerOptions()
        {
            GrantType = GrantType.ClientCredentials;
            CredentialsTransportMethod = CredentialsTransportMethod.BasicAuthenticationHeader;
            TokenRequestContentType = TokenRequestContentType.FormUrlEncoded;
        }
    }

    public class AccessTokenResponseOptions
    {
        private Func<string, IDictionary<string, object>> _responseDeserializer;

        public AccessTokenResponseOptionsKeyNames KeyNames { get; set; } = new AccessTokenResponseOptionsKeyNames();

        public void ConfigureDeserializer(Func<string, IDictionary<string, object>> responseDeserializer) => _responseDeserializer = responseDeserializer;

        public IDictionary<string, object> TryDeserialize(string responseAsString)
        {
            IDictionary<string, object> responseAsDictionary;
            try
            {
                if (_responseDeserializer != null)
                    responseAsDictionary = _responseDeserializer(responseAsString) ?? new Dictionary<string, object>();
                else
                    responseAsDictionary = new Dictionary<string, object>();
            }
            catch
            {
                responseAsDictionary = new Dictionary<string, object>();
            }
            return responseAsDictionary;
        }
    }

    public class AccessTokenResponseOptionsKeyNames
    {
        public string AccessToken { get; set; } = "access_token";

        public string TokenType { get; set; } = "token_type";

        public string ExpiresIn { get; set; } = "expires_in";

        public string RefreshToken { get; set; } = "refresh_token";

        public string Scope { get; set; } = "scope";

        public string RefreshTokenExpiresIn { get; set; } = "refresh_token_expires_in";
    }
}
