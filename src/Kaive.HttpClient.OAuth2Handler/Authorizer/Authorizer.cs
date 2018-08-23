using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Kaive.HttpClient.OAuth2Handler.Authorizer
{
    public class Authorizer : IAuthorizer
    {
        private readonly AuthorizerOptions _options;
        private readonly Func<System.Net.Http.HttpClient> _httpClientFactory;

        // ReSharper disable once UnusedMember.Global
        public Authorizer(AuthorizerOptions options)
            : this(options, () => new System.Net.Http.HttpClient())
        {
        }

        public Authorizer(AuthorizerOptions options, Func<System.Net.Http.HttpClient> httpClientFactory)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        }

        public async Task<TokenResponse> GetTokenAsync(CancellationToken? cancellationToken = null)
        {
            cancellationToken = cancellationToken ?? new CancellationToken(false);
            switch (_options.GrantType)
            {
                case GrantType.ClientCredentials:
                    return await GetTokenWithClientCredentials(cancellationToken.Value);
                case GrantType.ResourceOwnerPasswordCredentials:
                    return await GetTokenWithResourceOwnerPasswordCredentials(cancellationToken.Value);
                default:
                    throw new NotSupportedException($"Requested grant type '{_options.GrantType}' is not supported.");
            }
        }

        private Task<TokenResponse> GetTokenWithClientCredentials(CancellationToken cancellationToken)
        {
            if (_options.TokenEndpointUri == null) throw new ArgumentException("TokenEndpointUrl option cannot be null.");
            if (!_options.TokenEndpointUri.IsAbsoluteUri) throw new ArgumentException("TokenEndpointUrl must be an absolute Url.");

            var properties = new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" }
            };

            return GetTokenAsync(properties, cancellationToken);
        }

        private Task<TokenResponse> GetTokenWithResourceOwnerPasswordCredentials(CancellationToken cancellationToken)
        {
            if (_options.TokenEndpointUri == null) throw new ArgumentException("TokenEndpointUrl option cannot be null.");
            if (!_options.TokenEndpointUri.IsAbsoluteUri) throw new ArgumentException("TokenEndpointUrl must be an absolute Url.");

            if (_options.Username == null) throw new ArgumentException("Username cannot be null.");
            if (_options.Password == null) throw new ArgumentException("Password cannot be null.");

            var properties = new Dictionary<string, string>
            {
                { "grant_type", "password" },
                { "username", _options.Username },
                { "password", _options.Password }
            };

            return GetTokenAsync(properties, cancellationToken);
        }

        private async Task<TokenResponse> GetTokenAsync(IDictionary<string, string> properties, CancellationToken cancellationToken)
        {
            using (var client = _httpClientFactory())
            {
                if (_options.CredentialsTransportMethod == CredentialsTransportMethod.BasicAuthenticationCredentials)
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", GetBasicAuthorizationHeaderValue());
                else if (_options.CredentialsTransportMethod == CredentialsTransportMethod.FormAuthenticationCredentials)
                {
                    properties.Add("client_id", _options.ClientId);
                    properties.Add("client_secret", _options.ClientSecret);
                }

                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                if (_options.Scope != null)
                    properties.Add("scope", string.Join(" ", _options.Scope));

                if (_options.Resource != null)
                    properties.Add("resource", _options.Resource);

                var tokenUri = _options.TokenEndpointUri;
                if (_options.SetGrantTypeOnQueryString)
                    tokenUri = new UriBuilder(tokenUri) {Query = "grant_type=" + properties["grant_type"]}.Uri;

                var response = await client.PostAsync(tokenUri, new FormUrlEncodedContent(properties), cancellationToken);
                if (cancellationToken.IsCancellationRequested)
                    return null;

                if (!response.IsSuccessStatusCode)
                {
                    RaiseProtocolException(response.StatusCode, await response.Content.ReadAsStringAsync());
                    return null;
                }

                var serializer = new DataContractJsonSerializer(typeof(TokenResponse));
                return serializer.ReadObject(await response.Content.ReadAsStreamAsync()) as TokenResponse;
            }
        }

        private string GetBasicAuthorizationHeaderValue()
        {
            if (_options.ClientId == null) throw new ArgumentException("ClientId cannot be null.");
            if (_options.ClientSecret == null) throw new ArgumentException("ClientSecret cannot be null.");
            return Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_options.ClientId}:{_options.ClientSecret}"));
        }

        private void RaiseProtocolException(HttpStatusCode statusCode, string message)
        {
            if (_options.OnError != null)
                _options.OnError(statusCode, message);
            else
                throw new OAuthException(statusCode, message);
        }
    }
}
