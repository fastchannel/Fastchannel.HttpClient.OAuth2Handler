using System.Threading;
using System.Threading.Tasks;

namespace Kaive.HttpClient.OAuth2Handler.Authorizer
{
    public interface IAuthorizer
    {
        Task<TokenResponse> GetTokenAsync(CancellationToken? cancellationToken = null);
    }
}
