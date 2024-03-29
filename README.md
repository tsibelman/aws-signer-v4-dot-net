# aws-signer-v4-dot-net
Sign HttpRequestMessage using AWS Signature v4 using request information and credentials. 

Example of usage:
```csharp
    var signer = new AWS4RequestSigner("accessKey", "secretKey");
    var content = new StringContent("{...}", Encoding.UTF8, "application/json");
    var request = new HttpRequestMessage {
        Method = HttpMethod.Get,
        RequestUri = new Uri("https://apigateway.execute-api.us-west-2.amazonaws.com/Prod/api/data"),
        Content = content
    };

    request = await signer.Sign(request, "execute-api", "us-west-2");
    var client = new HttpClient();
    var response = await client.SendAsync(request);

    var responseStr = await response.Content.ReadAsStringAsync();
```
You can also download the source code and use the test project to test the library.
To do that just fill the configuration in the appsettings.json file and debug or run the test:

```json
{
  "access_key": "...",
  "secret_key": "...",
  "service": "execute-api",
  "region": "us-west-2",
  "request_uri": "https://apigateway.execute-api.us-west-2.amazonaws.com/Prod/api/data",
  "json": "{...}"
}
```

# Calling API Gateway with temporary credentials
When calling API Gateway (i.e. service `execute-api`) with temporary credentials, please also include AWS Session Token in request header:
```
request.Headers.TryAddWithoutValidation("X-Amz-Security-Token", "sessionToken");
```

### Calling from a sync method
In case you can't use async calls in your method, you can use this example instead
```csharp
    var signer = new AWS4RequestSigner("accessKey", "secretKey");
    var content = new StringContent("{...}", Encoding.UTF8, "application/json");
    var request = new HttpRequestMessage {
        Method = HttpMethod.Get,
        RequestUri = new Uri("https://apigateway.execute-api.us-west-2.amazonaws.com/Prod/api/data"),
        Content = content
    };

    request = signer.Sign(request, "execute-api", "us-west-2").ConfigureAwait(false).GetAwaiter().GetResult();
    var client = new HttpClient();
    var response = client.SendAsync(request).ConfigureAwait(false).GetAwaiter().GetResult();

    var responseStr = response.Content.ReadAsStringAsync().ConfigureAwait(false).GetAwaiter().GetResult();
```


### Nuget Package 
 Aws4RequestSigner is on NuGet: [Aws4RequestSigner](https://www.nuget.org/packages/Aws4RequestSigner/)
