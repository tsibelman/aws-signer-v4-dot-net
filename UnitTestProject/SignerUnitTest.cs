using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Aws4RequestSigner;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTestProject
{
    [TestClass]
    public class SignerUnitTest
    {
        private readonly string _AccessKey = "AKIAIKFJIWRFEHQSBXPA";
        private readonly string _secretKey = "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";
        private readonly string _service = "execute-api";
        private readonly string _region = "us-east-1";
        private readonly Uri _requestUri = new Uri("https://5jiocwdop2.execute-api.us-east-1.amazonaws.com/prod/api/direct-subscription");
        private readonly string _json = "{}";
        [TestMethod]
        public async Task TestSigner()
        {
            var signer = new Aws4RequestSigner.Aws4RequestSigner(_AccessKey, _secretKey);
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
