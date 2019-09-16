using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using AWS4RequestSigner;
using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTestProject
{
    [TestClass]
    public class SignerUnitTest
    {
        private readonly string _accessKey;
        private readonly string _secretKey;
        private readonly string _service;
        private readonly string _region;
        private readonly Uri _requestUri;
        private readonly string _json;

        public SignerUnitTest()
        {
            var config = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .Build();
            _accessKey = config["access_key"];
            _secretKey = config["secret_key"];
            _service = config["service"];
            _region = config["region"];
            _requestUri = new Uri(config["request_uri"]);
            _json = config["json"];
        }
        [TestMethod]
        public async Task TestSigner()
        {
            var signer = new AWS4RequestSigner.AWS4RequestSigner(_accessKey, _secretKey);
            var content = new StringContent(_json, Encoding.UTF8, "application/json");
            var request = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = _requestUri,
                Content = content
            };

            request = await signer.Sign(request, _service, _region);

            var client = new HttpClient();
            var response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
        }
    }
}
