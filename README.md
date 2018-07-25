# aws-signer-v4-dot-net
Sign HttpRequestMessage using AWS Signature v4 using request information and credentials. 

Example of usage:
```javascript
    var signer = new AWS4RequestSigner("accessKey", "secretKey");
    var request = new HttpRequestMessage {
        Method = HttpMethod.Get,
        RequestUri = new Uri("https://apigateway.execute-api.us-west-2.amazonaws.com/Prod/api/data")
    };

    request = await signer.Sign(request, "execute-api", "us-west-2");

    var client = new HttpClient();
    var response = await client.SendAsync(request);

    var responseStr = await response.Content.ReadAsStringAsync();
```

# Nuget Package

[Aws4RequestSigner](https://www.nuget.org/packages/Aws4RequestSigner/) is on NuGet.
