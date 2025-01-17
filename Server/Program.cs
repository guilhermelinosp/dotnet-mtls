using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Serilog;

var builder = WebApplication.CreateSlimBuilder(args);
var services = builder.Services;

builder.Host.UseSerilog((context, options) =>
	options.ReadFrom.Configuration(context.Configuration));

builder.WebHost.ConfigureKestrel(kestrel =>
{
	kestrel.ListenAnyIP(44378, options =>
	{
		options.UseHttps(https =>
		{
			try
			{
				https.ServerCertificate =
					X509CertificateLoader.LoadPkcs12(File.ReadAllBytes("keys/server.pfx"), "123456");
				https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
				https.ClientCertificateValidation = (cert, chain, sslPolicyErrors) =>
				{
					chain!.ChainPolicy.ExtraStore.Add(cert);

					return chain.Build(cert!) && sslPolicyErrors == SslPolicyErrors.None;
				};
			}
			catch (Exception ex)
			{
				Console.WriteLine($"Error setting up HTTPS: {ex.Message}");
				throw;
			}
		});
		options.UseConnectionLogging();
	});
});

services.AddDataProtection();

var app = builder.Build();

app.Use(async (context, next) =>
{
	if (context.Connection.ClientCertificate!.Subject != "CN=localhost")
	{
		context.Response.StatusCode = 403;
		await context.Response.WriteAsync("Invalid client certificate.");
		return;
	}

	await next();
});

app.MapGet("/", async context => { await context.Response.WriteAsync("Hello, TLS with mutual authentication!"); });
app.UseHttpsRedirection();

app.UseRouting();

await app.RunAsync();