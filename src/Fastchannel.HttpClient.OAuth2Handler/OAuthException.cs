using System;
using System.Net;

namespace Fastchannel.HttpClient.OAuth2Handler
{
    public class OAuthException : Exception
    {
        public HttpStatusCode StatusCode { get; }

        public OAuthException(HttpStatusCode statusCode, string message) : base(message)
        {
            StatusCode = statusCode;
        }
    }
}
