# Authentication, Authorization, STS, IdentityServer4

- [Authentication, Authorization, STS, IdentityServer4](#authentication-authorization-sts-identityserver4)
  - [Introduction](#introduction)
    - [OpenID Connect and OAuth 2.0 – better together](#openid-connect-and-oauth-20--better-together)
    - [History / other technologies](#history--other-technologies)
  - [PluralSight course [Securing Angular Apps with OpenID Connect and OAuth 2]](#pluralsight-course-securing-angular-apps-with-openid-connect-and-oauth-2)
    - [Brian Noyes](#brian-noyes)
    - [Introduction of the PluralSight course](#introduction-of-the-pluralsight-course)
    - [Authentication - Overview](#authentication---overview)
    - [Authorization - Overview](#authorization---overview)
  - [Authentication](#authentication)
    - [Terminology](#terminology)
      - [Identity Provider](#identity-provider)
      - [User Agent](#user-agent)
      - [Client](#client)
      - [Resource](#resource)
      - [Scope](#scope)
      - [JWT (Json Web Tokens)](#jwt-json-web-tokens)
  - [Authentication with OpenID Connect](#authentication-with-openid-connect)
    - [Identity Providers](#identity-providers)
    - [JavaScript Client Libraries](#javascript-client-libraries)
    - [OIDC - OpenID Connect](#oidc---openid-connect)
      - [Why OIDC](#why-oidc)
      - [JWT](#jwt)
      - [3 OIDC Flows](#3-oidc-flows)
        - [Authorization Code](#authorization-code)
        - [Hybrid](#hybrid)
        - [Implicit - deprecated *1)](#implicit---deprecated-1)
        - [Guidance](#guidance)
        - [Why did the recommendation change in 2019 *1)](#why-did-the-recommendation-change-in-2019-1)
    - [oidc-client](#oidc-client)
      - [Change flow Implicit -> Authorization Code](#change-flow-implicit---authorization-code)
      - [Auth0](#auth0)
        - [Fix Logout issue](#fix-logout-issue)
        - [Fix missing Access Token](#fix-missing-access-token)
        - [Complete settings](#complete-settings)
  - [Authorization - OAuth 2.0](#authorization---oauth-20)
    - [Terms](#terms)
      - [Resource Owner](#resource-owner)
      - [Resource Server](#resource-server)
      - [Client](#client-1)
      - [Authorization Server](#authorization-server)
    - [OAuth 2.0 Grant Types](#oauth-20-grant-types)
    - [Tokens](#tokens)
    - [Resource Server Responsibilities](#resource-server-responsibilities)
    - [Consent](#consent)
  - [Policy](#policy)
- [IdentityServer4](#identityserver4)
  - [Big Picture](#big-picture)
  - [Similar products](#similar-products)
  - [Use Cases](#use-cases)
  - [config](#config)
  - [Example "Quickstart 1": Protecting an API using Client Credentials](#example-quickstart-1-protecting-an-api-using-client-credentials)
    - [Create and Config Server](#create-and-config-server)
    - [Add API](#add-api)
    - [Add a Scope](#add-a-scope)
  - [Example "Quickstart 2": IdentityServer4 UI](#example-quickstart-2-identityserver4-ui)

## Introduction

### OpenID Connect and OAuth 2.0 – better together

OpenID Connect and OAuth 2.0 are very similar – in fact OpenID Connect is an extension on top of OAuth 2.0. The two fundamental security concerns, authentication and API access, are combined into a single protocol - often with a single round trip to the security token service.

### History / other technologies

The most common authentication protocols are:

- SAML2p (being the most popular and the most widely deployed)
- WS-Federation
- OpenID Connect

## PluralSight course [Securing Angular Apps with OpenID Connect and OAuth 2]

### Brian Noyes

Many thanks to Brian Noyes and his wonderful PluralSight course [Securing Angular Apps with OpenID Connect and OAuth 2](https://app.pluralsight.com/library/courses/openid-and-oauth2-securing-angular-apps/table-of-contents)

### Introduction of the PluralSight course

Important, but not really relevant in Angular Code (Web Server concerned)

- Transport Layer: use HTTPS (TLS) for everything
- CORS: Cross-Origin Resource Sharing
- CSRF: Cross Site Request Forgery (secure Cookies)
- XSS: Cross Site Scripting (be careful not to override Angular security implementation)

Angular (Client Side App) are always insecure: additional checks on the server-side needed

![OpenId Connect Overview](/images/oidc_overview.png)

### Authentication - Overview

- determine the user/client
- issue a temporary id
- details:
  - request credentials
  - collect credentials and validate
  - issue temporary credential (token) for specific app/api (scope)

### Authorization - Overview

- deciding what to allow
- not part of Authentication
- details
  - check and validate roles
  - look up and validate permissions
  - block / grant access to actions

## Authentication

### Terminology

#### Identity Provider

- STS (Security Token Service)
- Aspects
  - Authentication server
  - Authorization server
  - SSO server

#### User Agent

- piece of software the user is interacting with
- web app (in Angular Apps)
- operating system (might be if not in app)

#### Client

- piece of software
- web app (in Angular Apps)
- backend api
- batch process (without interacting user)
- software
  - that wants to access things outside of its control
  - and therefore needs to be authenticated

#### Resource

- the thing the user wants to access
- Web Api (in Angular Apps)
- app
- website, database, file store

#### Scope

- part of config
- represents the individual resources which the Identity Provider protects
- tells the Identity Provider what access is requested
- Google/Facebook/others: consent screens
- "high-level access control identifiers for a backend resource"

#### JWT (Json Web Tokens)

- identity token: user information
- access token: claims in the form scopes

## Authentication with OpenID Connect

### Identity Providers

- Google, Facebook, Twitter, ...
- Azure Active Directory (AAD)
  - v1 (no OpenId Connect)
  - v2 (OpenId Connect for MS and personal accounts (work/school accounts))
  - B2C: Business To Consumer (MS accounts, custom accounts)
- IaaS (Identity-as-a-service) providers
  - costly
  - easy to use
  - examples
    - Auth0
    - okta
    - Ping Identity
- IdentityServer4 (OpenID Connect certified)
  - identity provider framework
  - open source
  - requires coding and config
  - host yourself (azure web apps, vm, web servers)
  - most flexible option for Single Sign-On (SSO) federation scenarios

### JavaScript Client Libraries

- angular-jwt (minimal, no redirect, no return token evaluation)
- ADAL (not OpenId Connect, AAD v1 specific)
- MSAL (OpenId Connect but very AAD specific)
- oidc-client (OpenID Connect certified)

### OIDC - OpenID Connect

#### Why OIDC

![Open Id Connect Overview](/images/oidc_overview.png)

- Decoupling
- Enable Single Sign-On
- Centralized Security Management

#### JWT

- ID Token
- Access Token
- digitally signed
- not encrypted

#### 3 OIDC Flows

##### Authorization Code

- used in this course
- recommended for SPA (>= 2019)

##### Hybrid

- todo

##### Implicit - deprecated *1)

- was recommended for SPA (< 2019)
- deprecated *1)
- not really hacked: no need to change existing apps

##### Guidance

- OAuth 2.0 Security Best Current Practice
  - <https://tools.ietf.org/html/draft-ietf-oauth-security-topics-13>
  - <https://tools.ietf.org/html/draft-ietf-oauth-security-topics-14>
- OAuth 2.0 for Browser-Based Apps:
  - <https://tools.ietf.org/html/draft-ietf-oauth-browser-based-apps-05>

##### Why did the recommendation change in 2019 *1)

a) widespread browser support for

- CORS
- Same-site Cookies

b) Proof Key for Code Exchange (PKCE - "Pixie")

- Designed for native apps
- Good for JavaScript Client Apps and mobile apps
- Makes Authorization Code flow save for "public clients"
- Client generate and hash additional code/key, private to client, and STS
- Improvement on Implicit Flow hash fragment tokens vulnerability

### oidc-client

#### Change flow Implicit -> Authorization Code

To change the flow on the client, simply change the settings of the oidc-client library:

Implicit (old):

```typescript
response_type: 'id_token token'
```

Authorization Code (new):

```typescript
response_type: 'code'
```

Now change the server config accordingly.

#### Auth0

The client does not need any change - beside config changes.

##### Fix Logout issue

To logout, add an `end_session_endpoint`:

```typescript
end_session_endpoint: `${Constants.stsAuthority}v2/logout?client_id=${Constants.clientId}&returnTo=${encodeURI(Constants.clientRoot)}signout-callback`
```

##### Fix missing Access Token

To get an jwt instead of an id in `access_token`, add the audience:

```typescript
authorization_endpoint: `${Constants.stsAuthority}authorize?audience=projects-api`,
```

##### Complete settings

Get the urls from Auth0 in "Application", "Settings" tab, "Advanced settings", "Endpoints"

```typescript
constructor() {
    const stsSettings = {
      authority: Constants.stsAuthority,
      client_id: Constants.clientId,
      redirect_uri: `${Constants.clientRoot}signin-callback`,
      scope: 'openid profile projects-api',
      response_type: 'code',
      // post_logout_redirect_uri: `${Constants.clientRoot}signout-callback`,
      metadata: {
        issuer: `${Constants.stsAuthority}`,
        authorization_endpoint: `${Constants.stsAuthority}authorize?audience=projects-api`,
        jwks_uri: `${Constants.stsAuthority}.well-known/jwks.json`,
        token_endpoint: `${Constants.stsAuthority}oauth/token`,
        userinfo_endpoint: `${Constants.stsAuthority}userinfo`,
        end_session_endpoint: `${Constants.stsAuthority}v2/logout?client_id=${Constants.clientId}&returnTo=${encodeURI(Constants.clientRoot)}signout-callback`
      }
    };
    this._userManager = new UserManager(stsSettings);
  }
```

## Authorization - OAuth 2.0

<https://oauth.net/2/>

### Terms

#### Resource Owner

- has access to resource, or
- has ownership to the rights of the resource

#### Resource Server

- thing, protected by OAuth based access control
- can represent
  - web site
  - set of APIs
  - remotely accessible data store (like OPA)

#### Client

- piece of software, making the calls to the resource servers
- Angular app (in Angular Apps)
- Backend component, making calls to a downstream resource

#### Authorization Server

- a server application that manages the login and the issuing of access control token
- similar STS in Authentication

### OAuth 2.0 Grant Types

<https://oauth.net/2/grant-types/>

- Authorization Code (+PKCE)
- Implicit (deprecated)
- Resource Owner Password Credential
- Client Credential

### Tokens

- Access Token Content
  - client_id: Client Id
  - sub: Subject ID
  - iss: Issuer
  - nbf: Issue timestamp
  - exp: Expiration timestamp
  - aud: Audience
  - scope: Scope Claims
  - additional claims

- Refresh Token
  - long-lifetime tokens
  - not applicable to "public clients" (browser, mobile, web)
  - requires secure storage of refresh token
  - Angular: silent renewal of access tokens allows obtaining new access tokens when your current ones are expiring

### Resource Server Responsibilities

- Decode Token
- Validate Token
- Authorize Calls
- Expose Security Context API for Client

### Consent

- shows requested access rights
- often used in external providers
- configurable in server
- often not used internally

## Policy

ASP.NET Authorization Policy

# IdentityServer4

Source: <https://www.youtube.com/watch?v=nyUD-CeBSiE>

## Big Picture

<http://docs.identityserver.io/en/latest/intro/big_picture.html>

## Similar products

- PingFederate <https://developer.pingidentity.com/en/cloud-software/pingfederate.html>
- AAD <https://azure.microsoft.com/en-us/services/active-directory/>
- Okta
- Auth0

## Use Cases

- Authentication
- Chained Authentication
  - Twitter
  - Google
  - AAD
  - Windows Domain
- Multi Factor Login
- EULA Checkbox
- change to another provider without changing app
- protects/centralizes CI data (date of birth, ...)

## config

We need to configure:

- users
  - `IProfileService`
- clients
  - `IClientStore`
- resources, which needs to be protected (consuming apps)
  - `IResourceStore`

```cs
// activates IdentityServer4
// also activates cookie authentication middleware
app.UseIdentityServer();
```

Use or create a certificate (f.e., use `makeCert`). Add it to Local Computer\Personal\Certificates. Check it by using `certmgr.msc`.

```cs
services.AddIdentityServer() // adds core services
    .AddSigningCredential("CN=sts") // certificate (f.e., use `makeCert`, add it to Local Computer\Personal\Certificates. check `certmgr.msc`)
    .AddTestUsers(TestUser.Users) // add users
    .AddInMemoryClients(Config.GetClients()) // add clients
    .AddInMemoryIdentityResources(Config.GetIdentityResources()) // add identity resources
    .AddInMemoryApiResources(Config.GetApiResources()); // add api resources
```

Config client

```cs
public static IEnumerable<Client> GetClients(){
  return new Client[] {
    new Client {
      ClientId = "mvc",
      ClientName = "MVC Demo",
      AllowedGrantTypes = GrantTypes.Implicit,
      RedirectUris = { "http://localhost:25326/signing-oidc" }, // grab this from the client config
      AllowedScopes = { "openid", "email", "office" } // set up an "allowed list"
    }
  }
}
```

Config Identity Resources

```cs
public static IEnumerable<IdentityResource> GetIdentityResource(){
  return new IdentityResource[] {
    new IdentityResource.OpenId(), // well-known claims
    new IdentityResource.Email(),
    new IdentityResource.Profile(),
    new IdentityResource {
      Name = "office",
      UserClaims = { "office_number" }
    }
}
```

Config Users

```cs
public static List<TestUser> Users = new List<TestUser>{
  new TestUser { SubjectId = 818727, Username = "alice", Password = "alice",
    Claims = {
      new Claim ("office_number", "25"),
      new Claim (JwtClaimTypes.Name, "Alice Smith"),
      new Claim (JwtClaimTypes.GivenName, "Alice"),
      new Claim (JwtClaimTypes.FamilyName, "Smith"),
    }
  }
}
```

... TODO ...

## Example "Quickstart 1": Protecting an API using Client Credentials

From <http://docs.identityserver.io/en/latest/quickstarts/1_client_credentials.html>

Install or Update templates

`dotnet new -i IdentityServer4.Templates`

or

`dotnet new -i IdentityServer4.Templates –nuget-source https://api.nuget.org/v3/index.json`

### Create and Config Server

```cmd
md quickstart
cd quickstart
md src
cd src
dotnet new is4empty -n IdentityServer
cd ..
dotnet new sln -n Quickstart
dotnet sln add .\src\IdentityServer\IdentityServer.csproj
```

Add scope:

```cs
public static class Config
{
    public static IEnumerable<ApiScope> ApiScopes =>
        new List<ApiScope>
        {
            new ApiScope("api1", "My API")
        };
}
```

Define Client

```cs
public static IEnumerable<Client> Clients =>
    new List<Client>
    {
        new Client
        {
            ClientId = "client",

            // no interactive user, use the clientid/secret for authentication
            AllowedGrantTypes = GrantTypes.ClientCredentials,

            // secret for authentication
            ClientSecrets =
            {
                new Secret("secret".Sha256())
            },

            // scopes that client has access to
            AllowedScopes = { "api1" }
        }
    };
```

Config IdentityServer4

```cs
public void ConfigureServices(IServiceCollection services)
{
    var builder = services.AddIdentityServer()
        .AddDeveloperSigningCredential()        //This is for dev only scenarios when you don’t have a certificate to use.
        .AddInMemoryApiScopes(Config.ApiScopes)
        .AddInMemoryClients(Config.Clients);

    // omitted for brevity
}
```

Run it and test it:
`https://localhost:5001/.well-known/openid-configuration`

At first startup, IdentityServer will create a developer signing key for you, it’s a file called `tempkey.jwk`. You don’t have to check that file into your source control, it will be re-created if it is not present.

### Add API

```cmd
dotnet new webapi -n Api
cd ..
dotnet sln add .\src\Api\Api.csproj
dotnet add .\\src\\api\\Api.csproj package Microsoft.AspNetCore.Authentication.JwtBearer
```

Change applicationUrl in launchSettings.json to:
`"applicationUrl": "https://localhost:6001"`

Add a new Class:

```cs
[Route("identity")]
[Authorize]
public class IdentityController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        return new JsonResult(from c in User.Claims select new { c.Type, c.Value });
    }
}
```

In case `AddJwtBearer` is missing, add this nuget package: `Microsoft.AspNetCore.Authentication`

`<PackageReference Include="Microsoft.AspNetCore.Authentication.OpenIdConnect" Version="5.0.1" />`

Update Startup.cs

```cs
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddControllers();

        // add this config:
        services
          // adds the authentication services to DI and configures Bearer as the default scheme.
          .AddAuthentication("Bearer")
            .AddJwtBearer("Bearer", options =>
            {
                options.Authority = "https://localhost:5001";

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    // see: http://docs.identityserver.io/en/latest/topics/resources.html#refresources
                    ValidateAudience = false 
                };
            });
    }

    public void Configure(IApplicationBuilder app)
    {
        app.UseRouting();

        // adds the authentication middleware to the pipeline so authentication will be performed automatically on every call into the host.
        app.UseAuthentication(); // add this line

        // adds the authorization middleware to make sure, our API endpoint cannot be accessed by anonymous clients.
        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
        });
    }
}
```

For now, `https://localhost:6001/identity` will return 401

Add a client:

```cmd
dotnet new console -n Client
cd ..
dotnet sln add .\src\Client\Client.csproj
cd src
cd client
dotnet add package IdentityModel
```

Client Code:

```c#
using System;
using System.Net.Http;
using System.Threading.Tasks;
using IdentityModel.Client;

//.NET 5 top level statements (no class and namespace needed anymore)

Console.WriteLine("Hello World!");

// discover endpoints from metadata
var client = new HttpClient();
var disco = await client.GetDiscoveryDocumentAsync("https://localhost:5001");
if (disco.IsError)
{
    Console.WriteLine(disco.Error);
    return;
}

// request token
var tokenResponse = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
{
    Address = disco.TokenEndpoint,

    ClientId = "client",
    ClientSecret = "secret",
    Scope = "api1"
});

if (tokenResponse.IsError)
{
    Console.WriteLine(tokenResponse.Error);
    return;
}

Console.WriteLine(tokenResponse.Json);
```

Set all projects as startup (right-click on solution) and run them all by pressing F5.

>If you get an error connecting it may be that you are running https and the development certificate for `localhost` is not trusted. You can run `dotnet dev-certs https --trust` in order to trust the development certificate. This only needs to be done once.

Copy the string after `access_token` and paste it to `https://jwt.io/` to see the content.

Call the api:

```cs
// call api
var apiClient = new HttpClient();
apiClient.SetBearerToken(tokenResponse.AccessToken);

var response = await apiClient.GetAsync("https://localhost:6001/identity");
if (!response.IsSuccessStatusCode)
{
    Console.WriteLine(response.StatusCode);
}
else
{
    var content = await response.Content.ReadAsStringAsync();
    Console.WriteLine(JArray.Parse(content));
}
```

### Add a Scope

<http://docs.identityserver.io/en/latest/quickstarts/1_client_credentials.html#authorization-at-the-api>

Add this new policy rule to the API:

```cs
services.AddAuthorization(options =>
{
    options.AddPolicy("ApiScope", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.RequireClaim("scope", "api1");
    });
});
```

Enforce it in the API:

```cs
app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers()
        .RequireAuthorization("ApiScope");
});
```

Test it: change api1 to 2 (either on api or client side). You should get an error 400.

## Example "Quickstart 2": IdentityServer4 UI

source: <<http://docs.identityserver.io/en/latest/quickstarts/2_interactive_aspnetcore.htm>

```cmd
md src
cd src
md IdentityServer
cd IdentityServer
rem is4inmem combines a basic IdentityServer including the standard UI.
dotnet new is4inmem
cd..
dotnet new mvc -n MvcClient
dotnet sln add .\MvcClient\MvcClient.csproj
cd MvcClient
dotnet add package Microsoft.AspNetCore.Authentication.OpenIdConnect
```

Add this to `ConfigureServices` in StartUp.cs:

```cs
// add the following lines

JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

services.AddAuthentication(options =>
    {
        options.DefaultScheme = "Cookies";
        options.DefaultChallengeScheme = "oidc";
    })
    .AddCookie("Cookies")
    .AddOpenIdConnect("oidc", options =>
    {
        options.Authority = "https://localhost:5001";

        options.ClientId = "mvc";
        options.ClientSecret = "secret";
        options.ResponseType = "code";

        options.SaveTokens = true;
    });
```

>We use the `authorization code flow with PKCE` to connect to the OpenID Connect provider. <http://docs.identityserver.io/en/latest/topics/grant_types.html#refgranttypes>

```cs
app.UseAuthentication(); // add this line
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapDefaultControllerRoute() // add this lines
        .RequireAuthorization(); // adds [Authorize] attribute to all controllers
});
```

Show Users and Claims in Home\Index.cshtml

```cs
@using Microsoft.AspNetCore.Authentication

<h2>Claims</h2>

<dl>
    @foreach (var claim in User.Claims)
    {
        <dt>@claim.Type</dt>
        <dd>@claim.Value</dd>
    }
</dl>

<h2>Properties</h2>

<dl>
    @foreach (var prop in (await Context.AuthenticateAsync()).Properties.Items)
    {
        <dt>@prop.Key</dt>
        <dd>@prop.Value</dd>
    }
</dl>
```

Check config: added Users, IdentityResources, ApiScopes, Clients.

Add Client config for Quickstart 2:

```cs
// "Quickstart 2": interactive ASP.NET Core MVC client
new Client
{
    ClientId = "mvc",
    ClientSecrets = { new Secret("secret".Sha256()) },

    AllowedGrantTypes = GrantTypes.Code,

    // where to redirect to after login
    RedirectUris = { "https://localhost:5002/signin-oidc" },

    // where to redirect to after logout
    PostLogoutRedirectUris = { "https://localhost:5002/signout-callback-oidc" },

    AllowedScopes = new List<string>
    {
        IdentityServerConstants.StandardScopes.OpenId,
        IdentityServerConstants.StandardScopes.Profile
    }
},
```

TODO: next: use this in the Angular example
