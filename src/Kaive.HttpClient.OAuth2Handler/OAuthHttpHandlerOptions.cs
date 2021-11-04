using System.Net.Http;
using Kaive.HttpClient.OAuth2Handler.Authorizer;

namespace Kaive.HttpClient.OAuth2Handler
{
    public class OAuthHttpHandlerOptions
    {
        public AuthorizerOptions AuthorizerOptions { get; set; }

        public HttpMessageHandler InnerHandler { get; set; }

        public bool HttpClientFactoryEnabled { get; set; }

        public bool IgnoreRefreshTokens { get; set; }

        // ReSharper disable once UnusedMember.Global
        public OAuthHttpHandlerOptions()
        {
            AuthorizerOptions = new AuthorizerOptions();
        }
    }
}
