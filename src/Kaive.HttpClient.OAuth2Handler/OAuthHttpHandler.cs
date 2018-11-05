using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Kaive.HttpClient.OAuth2Handler.Authorizer;

namespace Kaive.HttpClient.OAuth2Handler
{
    // ReSharper disable once UnusedMember.Global
    public class OAuthHttpHandler : DelegatingHandler
    {
        private readonly bool _ownsHandler;
        private readonly IAuthorizer _authorizer;

        private TokenResponse _tokenResponse;
        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(1, 1);

        // ReSharper disable once UnusedMember.Global
        public OAuthHttpHandler(OAuthHttpHandlerOptions options)
        {
            var config = options ?? throw new ArgumentNullException(nameof(options));

            if (!config.HttpClientFactoryEnabled)
            {
                InnerHandler = config.InnerHandler ?? new HttpClientHandler();
                _ownsHandler = config.InnerHandler == null;
            }

            _authorizer =
                new Authorizer.Authorizer(config.AuthorizerOptions, () =>
                {
                    if (!config.HttpClientFactoryEnabled)
                        return new System.Net.Http.HttpClient(InnerHandler, false);

                    if (config.InnerHandler != null)
                        return new System.Net.Http.HttpClient(config.InnerHandler);

                    return new System.Net.Http.HttpClient();
                });
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing && _ownsHandler)
                InnerHandler.Dispose();
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Headers.Authorization == null)
            {
                var tokenResponse = await GetTokenResponse(cancellationToken);
                if (tokenResponse != null)
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenResponse.AccessToken);
            }

            var response = await base.SendAsync(request, cancellationToken);
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                var tokenResponse = await RefreshTokenResponse(cancellationToken);
                if (tokenResponse != null)
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenResponse.AccessToken);
                    response = await base.SendAsync(request, cancellationToken);
                }
            }

            return response;
        }

        private async Task<TokenResponse> GetTokenResponse(CancellationToken cancellationToken)
        {
            try
            {
                _semaphore.Wait(cancellationToken);
                if (cancellationToken.IsCancellationRequested) return null;
                _tokenResponse = _tokenResponse ?? await _authorizer.GetTokenAsync(cancellationToken);
                return _tokenResponse;
            }
            finally
            {
                _semaphore.Release();
            }
        }

        private async Task<TokenResponse> RefreshTokenResponse(CancellationToken cancellationToken)
        {
            try
            {
                _semaphore.Wait(cancellationToken);
                if (cancellationToken.IsCancellationRequested) return null;
                _tokenResponse = await _authorizer.GetTokenAsync(cancellationToken);
                return _tokenResponse;
            }
            finally
            {
                _semaphore.Release();
            }
        }
    }
}
