# Authentication, Authorization

- [Authentication, Authorization](#authentication-authorization)
  - [Brian Noyes](#brian-noyes)
  - [Introduction](#introduction)
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

## Brian Noyes

Many thanks to Brian Noyes and his wonderful Pluralsight course [Securing Angular Apps with OpenID Connect and OAuth 2](https://app.pluralsight.com/library/courses/openid-and-oauth2-securing-angular-apps/table-of-contents)

## Introduction

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
