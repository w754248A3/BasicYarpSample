using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using LeiKaiFeng.X509Certificates;
using System.IO;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace BasicYARPSample
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // Create a Kestrel web server, and tell it to use the Startup class
            // for the service configuration

            var tls = TLSHelper.CreateFromFile("ca.pfx");

            

            var myHostBuilder = Host.CreateDefaultBuilder(args);
                
            
            myHostBuilder.ConfigureWebHostDefaults(webHostBuilder =>
            {
                webHostBuilder.UseStartup<Startup>();


                webHostBuilder.ConfigureKestrel(serverOptions =>
                {
                    serverOptions.ListenLocalhost(443, listenOptions =>
                    {
                        listenOptions.UseHttps(httpsOptions =>
                        {
                            httpsOptions.ServerCertificateSelector = (connectionContext, name) =>
                            {
                                var sni = name ?? "baidu.com";

                                var tlsCert = tls.CreateTlsCert(
                                      "iwara.tv",
                                      2048,
                                      30000,
                                      new string[] { sni });


                                return tlsCert;
                            };

                        });
                    });
                });


            });
            var myHost = myHostBuilder.Build();
            myHost.Run();
        }
    }


    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            // Default configuration comes from AppSettings.json file in project/output
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add capabilities to
        // the web application via services in the DI container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add the reverse proxy capability to the server
            var proxyBuilder = services.AddReverseProxy();
            // Initialize the reverse proxy from the "ReverseProxy" section of configuration
            proxyBuilder.LoadFromConfig(Configuration.GetSection("ReverseProxy"));
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request 
        // pipeline that handles requests
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {

            // Enable endpoint routing, required for the reverse proxy
            app.UseRouting();
            // Register the reverse proxy routes
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapReverseProxy();
            });
        }
    }
}
