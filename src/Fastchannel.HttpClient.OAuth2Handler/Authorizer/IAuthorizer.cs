using System.Threading;
using System.Threading.Tasks;

namespace Fastchannel.HttpClient.OAuth2Handler.Authorizer
{
    public interface IAuthorizer
    {
        Task<TokenResponse> GetTokenAsync(CancellationToken? cancellationToken = null);

        Task<TokenResponse> GetTokenAsync(GrantType? grantType, string refreshToken, CancellationToken? cancellationToken = null);
    }
}
