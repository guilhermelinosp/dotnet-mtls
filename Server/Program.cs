using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Serilog;

try
{
	var builder = WebApplication.CreateSlimBuilder(args);

	builder.Host.UseSerilog((context, options) =>
		options.ReadFrom.Configuration(context.Configuration));

	builder.WebHost.ConfigureKestrel(kestrel =>
	{
		kestrel.ListenAnyIP(44378, options =>
		{
			options.UseHttps(https =>
			{
				https.ServerCertificate =
					X509CertificateLoader.LoadPkcs12FromFile("keys/server.pfx", "123456");
				https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
				
				https.ClientCertificateValidation = (cert, chain, sslPolicyErrors) =>
				{
					chain!.ChainPolicy.ExtraStore.Add(X509CertificateLoader.LoadCertificateFromFile("keys/ca.pem"));
					
					chain!.Build(cert!);

					return sslPolicyErrors != SslPolicyErrors.None;
				};
			});
			options.UseConnectionLogging();
		});
	});

	builder.Services.AddDataProtection();

	var app = builder.Build();

	app.Use(async (context, next) =>
	{
		if (context.Connection.ClientCertificate is not { Subject: "CN=client.local" })
		{
			context.Response.StatusCode = 403;
			await context.Response.WriteAsync("Invalid client certificate.");
			return;
		}

		await next();
	});

	app.MapGet("/", async context => { await context.Response.WriteAsync("Hello, TLS with mutual authentication!"); });

	await app.RunAsync();
}
catch (Exception ex)
{
	Console.WriteLine($"Exception: {ex.Message}");
	Console.WriteLine($"Inner Exception: {ex.InnerException!.Message}");
	Console.WriteLine("Stack Trace: " + ex.StackTrace);
}