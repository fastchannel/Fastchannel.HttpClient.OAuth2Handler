# OAuth2 HttpClient Handler, by Fastchannel

![Build status](https://img.shields.io/appveyor/build/fastchannel/fastchannel-httpclient-oauth2handler?style=plastic)

![Install from nuget](https://img.shields.io/nuget/v/Fastchannel.HttpClient.OAuth2Handler?style=plastic)

Managed .NET library to be used within HttpClient instances,
enabling them to transparantly call authorized remote APIs protected with **OAuth2** or **OpenID-Connect** standards.

Supports .NET Framework 4.5+ and .NET Standard / .NET Core.

## Get it on NuGet

    PM> Install-Package Fastchannel.HttpClient.OAuth2Handler

## Basic Usage

```C#
var options = new OAuthHttpHandlerOptions
{
    AuthorizerOptions = new AuthorizerOptions
    {
        TokenEndpointUrl = new Uri("https://localhost/token"),
        GrantType = GrantType.ClientCredentials,
        ClientId = "SomeClientId",
        ClientSecret = "SomeClientSecret"
    }
};

using (var client = new HttpClient(new OAuthHttpHandler(options)))
{
    client.BaseAddress = new Uri("http://localhost");
    var response = await client.GetAsync("/api/protected_api_call");
    // ...
}
```
