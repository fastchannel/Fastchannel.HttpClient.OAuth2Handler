using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;

namespace Kaive.HttpClient.OAuth2Handler.Authorizer
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

        public Action<HttpStatusCode, string> OnError { get; set; }

        public Action<HttpRequestMessage, string> OnTokenRefresh { get; set; }

        public AuthorizerOptions()
        {
            CredentialsTransportMethod = CredentialsTransportMethod.BasicAuthenticationCredentials;
        }
    }
}
