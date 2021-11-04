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
        private const string CredentialsKey_GrantType = "grant_type";
        private const string CredentialsKey_Username = "username";
        private const string CredentialsKey_Password = "password";
        private const string CredentialsKey_RefreshToken = "refresh_token";
        private const string CredentialsKey_ClientId = "client_id";
        private const string CredentialsKey_ClientSecret = "client_secret";
        private const string CredentialsKey_Scope = "scope";
        private const string CredentialsKey_Resource = "resource";

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

            SetDefaultCredentialsKeyNames();
        }

        private void SetDefaultCredentialsKeyNames()
        {
            var defaultKeyNames = new Dictionary<string, string>
            {
                { CredentialsKey_GrantType, CredentialsKey_GrantType },
                { CredentialsKey_Username, CredentialsKey_Username },
                { CredentialsKey_Password, CredentialsKey_Password },
                { CredentialsKey_ClientId, CredentialsKey_ClientId },
                { CredentialsKey_ClientSecret, CredentialsKey_ClientSecret },
                { CredentialsKey_Scope, CredentialsKey_Scope },
                { CredentialsKey_Resource, CredentialsKey_Resource }
            };

            if (_options.CredentialsKeyNames == null || _options.CredentialsKeyNames.Keys.Count == 0)
            {
                _options.CredentialsKeyNames = defaultKeyNames;
                return;
            }

            foreach(var keyName in defaultKeyNames.Keys)
            {
                if (_options.CredentialsKeyNames.ContainsKey(keyName))
                    continue;

                _options.CredentialsKeyNames.Add(keyName, defaultKeyNames[keyName]);
            }
        }

        private string GetKeyName(string credentialKey) => _options.CredentialsKeyNames[credentialKey];

        public async Task<TokenResponse> GetTokenAsync(CancellationToken? cancellationToken = null)
            => await GetTokenAsync(null, null, cancellationToken);

        public async Task<TokenResponse> GetTokenAsync(GrantType? grantType, string refreshToken, CancellationToken? cancellationToken = null)
        {
            cancellationToken = cancellationToken ?? new CancellationToken(false);
            var effectiveGrantType = grantType ?? _options.GrantType;
            switch (effectiveGrantType)
            {
                case GrantType.ClientCredentials:
                    return await GetTokenWithClientCredentials(cancellationToken.Value);
                case GrantType.ResourceOwnerPasswordCredentials:
                    return await GetTokenWithResourceOwnerPasswordCredentials(cancellationToken.Value);
                case GrantType.RefreshToken:
                    return await GetTokenWithRefreshToken(refreshToken, cancellationToken.Value);
                default:
                    throw new NotSupportedException($"Requested grant-type '{_options.GrantType}' is not supported.");
            }
        }

        private Task<TokenResponse> GetTokenWithClientCredentials(CancellationToken cancellationToken)
        {
            if (_options.TokenEndpointUri == null) throw new ArgumentException("TokenEndpointUrl option cannot be null.");
            if (!_options.TokenEndpointUri.IsAbsoluteUri) throw new ArgumentException("TokenEndpointUrl must be an absolute Url.");

            var properties = new Dictionary<string, string>
            {
                { GetKeyName(CredentialsKey_GrantType), "client_credentials" }
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
                { GetKeyName(CredentialsKey_GrantType), "password" },
                { GetKeyName(CredentialsKey_Username), _options.Username },
                { GetKeyName(CredentialsKey_Password), _options.Password }
            };

            return GetTokenAsync(properties, cancellationToken);
        }

        private Task<TokenResponse> GetTokenWithRefreshToken(string refreshToken, CancellationToken cancellationToken)
        {
            if (_options.TokenEndpointUri == null) throw new ArgumentException("TokenEndpointUrl option cannot be null.");
            if (!_options.TokenEndpointUri.IsAbsoluteUri) throw new ArgumentException("TokenEndpointUrl must be an absolute Url.");

            if (_options.Username == null) throw new ArgumentException("Username cannot be null.");
            if (_options.Password == null) throw new ArgumentException("Password cannot be null.");

            var properties = new Dictionary<string, string>
            {
                { GetKeyName(CredentialsKey_GrantType), "refresh_token" },
                { GetKeyName(CredentialsKey_RefreshToken), refreshToken }
            };

            return GetTokenAsync(properties, cancellationToken);
        }

        private async Task<TokenResponse> GetTokenAsync(IDictionary<string, string> properties, CancellationToken cancellationToken)
        {
            using (var client = _httpClientFactory())
            {
                if (_options.CredentialsTransportMethod == CredentialsTransportMethod.BasicAuthenticationCredentials)
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", GetBasicAuthorizationHeaderValue());
                else
                {
                    properties.Add(GetKeyName(CredentialsKey_ClientId), _options.ClientId);
                    properties.Add(GetKeyName(CredentialsKey_ClientSecret), _options.ClientSecret);
                }

                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                if (_options.Scope != null)
                    properties.Add(GetKeyName(CredentialsKey_Scope), string.Join(" ", _options.Scope));

                if (_options.Resource != null)
                    properties.Add(GetKeyName(CredentialsKey_Resource), _options.Resource);

                var tokenUri = _options.TokenEndpointUri;
                if (_options.SetGrantTypeOnQueryString)
                    tokenUri = new UriBuilder(tokenUri) {Query = $"{GetKeyName(CredentialsKey_GrantType)}={properties[GetKeyName(CredentialsKey_GrantType)]}"}.Uri;

                var requestContent = _options.CredentialsTransportMethod != CredentialsTransportMethod.JsonAuthenticationCredentials
                    ? (HttpContent) new FormUrlEncodedContent(properties)
                    : CreateJsonRequestContent(properties);

                var response = await client.PostAsync(tokenUri, requestContent, cancellationToken);
                if (cancellationToken.IsCancellationRequested)
                    return null;

                if (!response.IsSuccessStatusCode)
                {
                    RaiseProtocolException(response.StatusCode, await response.Content.ReadAsStringAsync());
                    return null;
                }

                if (_options.AccessTokenResponseOptions == null)
                {
                    var serializer = new DataContractJsonSerializer(typeof(TokenResponse));
                    return serializer.ReadObject(await response.Content.ReadAsStreamAsync()) as TokenResponse;
                }
                else
                {
                    var responseAsDictionary = _options.AccessTokenResponseOptions.TryDeserialize(await response.Content.ReadAsStringAsync());
                    var responseKeyNames = _options.AccessTokenResponseOptions.KeyNames;
                    if (!responseAsDictionary.ContainsKey(responseKeyNames.AccessToken))
                        return null;

                    try
                    {
                        var tokenResponse = new TokenResponse
                        {
                            AccessToken = responseAsDictionary[responseKeyNames.AccessToken]?.ToString(),
                            TokenType = responseAsDictionary[responseKeyNames.TokenType]?.ToString(),
                            ExpiresInSeconds = Convert.ToDouble(responseAsDictionary[responseKeyNames.ExpiresIn]),
                            Scope = responseAsDictionary[responseKeyNames.Scope]?.ToString(),
                            RefreshToken = responseAsDictionary[responseKeyNames.RefreshToken]?.ToString(),
                            RefreshTokenExpiresInSeconds = Convert.ToDouble(responseAsDictionary[responseKeyNames.RefreshTokenExpiresIn]),
                        };

                        if (string.IsNullOrWhiteSpace(tokenResponse.AccessToken))
                            return null;

                        return tokenResponse;
                    }
                    catch
                    {
                        return null;
                    }
                }
            }
        }

        private StringContent CreateJsonRequestContent(IDictionary<string, string> requestData)
        {
            using (var memStream = new System.IO.MemoryStream())
            using (var streamReader = new System.IO.StreamReader(memStream))
            {
                var jsonSerializer = new DataContractJsonSerializer(typeof(IDictionary<string, string>),
                    new DataContractJsonSerializerSettings()
                    {
                        UseSimpleDictionaryFormat = true
                    });

                jsonSerializer.WriteObject(memStream, requestData);

                memStream.Position = 0;
                var jsonString = streamReader.ReadToEnd();

                return new StringContent(jsonString, Encoding.UTF8, "application/json");
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
