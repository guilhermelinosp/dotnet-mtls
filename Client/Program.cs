using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

try
{
	using var client = new HttpClient(new HttpClientHandler
	{
		ClientCertificates = { X509CertificateLoader.LoadPkcs12(File.ReadAllBytes("keys/client.pfx"), "123456") },
		ServerCertificateCustomValidationCallback = (_, cert, chain, sslPolicyErrors) =>
		{
			chain!.ChainPolicy.ExtraStore.Add(cert!);

			return chain.Build(cert!) && sslPolicyErrors == SslPolicyErrors.None;
		}
	});

	Console.WriteLine("Sending request to the server...");

	var response = await client.GetAsync("https://localhost:44378");

	response.EnsureSuccessStatusCode();

	Console.WriteLine(
		$"Server response: Status {response.StatusCode}, Content: {response.Content.ReadAsStringAsync().Result}");
}
catch (Exception ex)
{
	Console.WriteLine($"Exception: {ex.Message}");
	Console.WriteLine($"Inner Exception: {ex.InnerException!.Message}");
	Console.WriteLine("Stack Trace: " + ex.StackTrace);
}