# IdentityServer4 - TODO - NOT WORKING - NOT FINISHED

## Implementation

<https://www.scottbrady91.com/Identity-Server/Getting-Started-with-IdentityServer-4>

## Test Endpoint

<https://localhost:5001/.well-known/openid-configuration>

## Add Certificate

More information: <https://letsencrypt.org/docs/certificates-for-localhost/>

### Add DNS in hosts

For the certificate to be accepted in the browser, a DNS is needed.

Example: `www.identityserver4.dev`

fyi: There should be a dot (.) in it.

We can fake a DNS by add an entry in hosts file.

As admin, edit c:\Windows\System32\drivers\etc\hosts, add the following line:

`127.0.0.1 www.identityserver4.dev`

After saving, the IdentityServer is available under this DNS: `https://www.identityserver4.dev:5001/`

Because there is no cert yet, you'll get an cert error.

### Add Certificate for DNS

Run as Admin in PowerShell:

```ps
$cert = New-SelfSignedCertificate -DnsName "www.identityserver4.dev" -CertStoreLocation "cert:\LocalMachine\My"
```

Run `$cert` to see it:

```
PS C:\WINDOWS\system32> $cert

   PSParentPath: Microsoft.PowerShell.Security\Certificate::LocalMachine\My

Thumbprint                                Subject                                                                                                                                                                  
----------                                -------                                                                                                                                                                  
C0016B3DEB47FB1E98C430252C88D44310CFF2EB  CN=www.identityserver4.dev            
```

### Trust the certificate

Put it in the needed store:

```ps
$DestStore = new-object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreName]::Root,"localmachine")
$DestStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$DestStore.Add($cert)
$DestStore.Close()
```

Source: <https://mattou07.net/posts/create-a-self-signed-certificate-for-iis-with-powershell/>

### Use Certificate

There are other ways to use the certificate. I am using IIS for now.

1. Install IIS (add IIS in Windows Features)
2. In Visual Studio "Get Tools and Features", add "Development time IIS support"
3. Project Properties: Debug:
 - Select Launch: "IIS"
 - [x] Launch Browser: <https://www.identityserver4.dev> (the one you created above)

Source and Details: <https://devblogs.microsoft.com/aspnet/development-time-iis-support-for-asp-net-core-applications/>
Or <https://docs.microsoft.com/en-us/aspnet/core/host-and-deploy/iis/development-time-iis-support?view=aspnetcore-3.1>

Configure IIS

- Physical Path: C:\Work.proj\IdentityServer4Server\Server (use your path to the server csproj here)
- Type: https, Port: 443
- SSL Certificate: select www.identityserver4.dev (the one you created above)

> Chrome is happy now! :) BUT Firefox and Postman aren't :(

<https://www.identityserver4.dev/.well-known/openid-configuration>

### Postman error

```json
{
    "error": "invalid_client"
}
```

> ERROR: Unable to verify the first certificate

### Interesting, but did not help

#### export cert to cert.pfx

convert cert to crt/key: <https://www.markbrilman.nl/2011/08/howto-convert-a-pfx-to-a-seperate-key-crt-file/>
DID NOT HELP

#### Create OpenSSL Certificate

Run in wsl 2: (Get it from Store, run the new Icon in Start Menu)

```
openssl req -x509 -out www.localhost.crt -keyout www.localhost.key \
  -newkey rsa:2048 -nodes -sha256 \
  -subj '/CN=www.localhost' -extensions EXT -config <( \
   printf "[dn]\nCN=www.localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:www.localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
```

Source: <https://letsencrypt.org/docs/certificates-for-localhost/>

Grab the files from Ubuntu in Windows by File Explorer: `\\wsl$\Ubuntu-20.04\home\bop`

#### Convert crt/key to pfx

> use winpty under Windows (otherwise openssl will hang)

`winpty openssl pkcs12 -export -out certificate.pfx -inkey www.localhost.key -in www.localhost.crt`

Source: todo

## Get Token

```
POST /connect/token

Headers:
Content-Type: application/x-www-form-urlencoded

Body:
grant_type=client_credentials&scope=api1.read&client_id=oauthClient&client_secret=superSecretPassword
```

### CURL

Download curl for windows. use ' -k or --insecure' to overcome the ssl issue.
source: <https://curl.haxx.se/docs/sslcerts.html>

```
curl --location --request POST "https://www.identityserver4.dev/connect/token" --header "Content-Type: application/x-www-form-urlencoded" --data-urlencode "grant_type=client_credentials" --data-urlencode "scope=api1.read" --data-urlencode "client_id=oauthClient" --data-urlencode "client_secret=superSecretPassword" --insecure
```

Error:

```json
{
    "error": "invalid_client"
}
```

From Log Trace: No matching hashed secret found

Todo:

- sent hashed secret: did not help
- where is the problem ???

Temporary solution: disable secret validation

```cs
RequireClientSecret = false // for debugging
```
