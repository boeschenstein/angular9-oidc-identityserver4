using System;
using System.Net.Http;
using System.Text.Json;
using IdentityModel.Client;
using Newtonsoft.Json.Linq;

Console.WriteLine("Hello World!");

// https://www.strathweb.com/2020/10/beautiful-and-compact-web-apis-with-c-9-net-5-0-and-asp-net-core/

Console.WriteLine("API: starting");

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
    Scope = "api1",
    //Scope = "api2", // check it: does not work anymore (not configured in the api)
});

if (tokenResponse.IsError)
{
    Console.WriteLine(tokenResponse.Error);
    return;
}

Console.WriteLine(tokenResponse.Json);

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
    Console.WriteLine(JsonDocument.Parse(content));
    Console.WriteLine(JArray.Parse(content));
}

//namespace Client
//{
//class Program
//    {
//        static async Task Main(string[] args)
//        {
//            Console.WriteLine("Hello World!");

//             ... for .NET Core 3.1, put all the code from above at this place ...

//        }
//    }
//}