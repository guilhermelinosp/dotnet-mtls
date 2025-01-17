using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

try
{
	using var client = new HttpClient(new HttpClientHandler
	{
		ClientCertificates = { X509CertificateLoader.LoadPkcs12FromFile("keys/client.pfx", "123456") },
		
		ServerCertificateCustomValidationCallback = (_, cert, chain, sslPolicyErrors) =>
		{
			chain!.ChainPolicy.ExtraStore.Add(X509CertificateLoader.LoadCertificateFromFile("keys/ca.pem"));

			chain!.Build(cert!);

			return sslPolicyErrors != SslPolicyErrors.None;
		}
	});

	Console.WriteLine("Sending request to the server...");

	var response = await client.GetAsync("https://localhost:44378").ConfigureAwait(false);

	response.EnsureSuccessStatusCode();

	Console.WriteLine(
		$"Server response: Status {response.StatusCode}, Content: {await response.Content.ReadAsStringAsync().ConfigureAwait(false)}");
}
catch (Exception ex)
{
	Console.WriteLine($"Exception: {ex.Message}");
	if (ex.InnerException != null)
	{
		Console.WriteLine($"Inner Exception: {ex.InnerException.Message}");
	}
	Console.WriteLine("Stack Trace: " + ex.StackTrace);
}