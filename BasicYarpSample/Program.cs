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
using System.Text.Json.Serialization;
using System.Text.Json;
using System.Diagnostics;

namespace BasicYARPSample
{

    public sealed class Policies
    {
        public Certificates Certificates { get; set; }

        public bool DisableAppUpdate { get; set; }

        public bool DontCheckDefaultBrowser { get; set; }

        public string OverrideFirstRunPage { get; set; }
    }

    public sealed class Certificates
    {
        public string[] Install { get; set; }
    }


    public sealed class FirefoxPolicies
    {
        [JsonPropertyName("policies")]
        public Policies Policies { get; set; }
    }
    

    public class Program
    {

        static void CreateFirefoxPoliciesJsonFile(string caPemPath, string firefoxPath)
        {
           
            var policies = new FirefoxPolicies();


            policies.Policies = new Policies();

            policies.Policies.Certificates = new Certificates();

            policies.Policies.Certificates.Install = new string[] { caPemPath };

            policies.Policies.DisableAppUpdate = true;

            policies.Policies.DontCheckDefaultBrowser = true;

            policies.Policies.OverrideFirstRunPage = "";


            var policiesPath = Path.Combine(firefoxPath, "distribution");

            Directory.CreateDirectory(policiesPath);

            policiesPath = Path.Combine(policiesPath, "policies.json");



            File.WriteAllText(policiesPath, JsonSerializer.Serialize(policies), new System.Text.UTF8Encoding(false));

        }

        static string GetFirefoxPath()
        {
            var path = AppDomain.CurrentDomain.BaseDirectory;

            return Path.Combine(path, "Firefox");

        }

        static string GetFirefoxUserFile()
        {
            var path = AppDomain.CurrentDomain.BaseDirectory;

            path = Path.Combine(path, "FirefoxUser");

            Directory.CreateDirectory(path);

            return path;
        }

        static void CreateUserInfoFile(string path)
        {
            path = Path.Combine(path, "user.js");

            var vs = new string[]
            {
                "user_pref('network.dns.forceResolve', '127.0.0.1');",
                "user_pref('network.proxy.type', 0);"
            };


            var s = string.Join(Environment.NewLine, vs).Replace("'", "\"");


            File.WriteAllText(path, s, new System.Text.UTF8Encoding(false));





        }

        static string GetCAPemPath()
        {
            var path = AppDomain.CurrentDomain.BaseDirectory;

            return Path.Combine(path, "ca.pem");
        }


        static string GetFirefoxAppPath()
        {
            return Path.Combine(GetFirefoxPath(), "firefox.exe");
        }

        static void RunFirefox(string appPath, string userPath)
        {
            var info = new ProcessStartInfo();

            var vs = new string[] { "-profile", "\"" + userPath + "\"" };



            info.UseShellExecute = false;
            info.FileName = appPath;
            info.WorkingDirectory = Path.GetDirectoryName(appPath);
            info.Arguments = string.Join(" ", vs);

            Process.Start(info);


        }

        public static void Main(string[] args)
        {
            var tls = TLSHelper.CreateCaCert("LEIKAIFENG CA ROOT", 2048, 300);


            var ca = tls.AsToX509Certificate2().AsPemCert();

            var capem = GetCAPemPath();

            File.WriteAllBytes(capem, ca);

            
            CreateFirefoxPoliciesJsonFile(capem, GetFirefoxPath());

            CreateUserInfoFile(GetFirefoxUserFile());




            RunFirefox(GetFirefoxAppPath(), GetFirefoxUserFile());

            RunAsp(args, tls);
        }


        static void RunAsp(string[] args, TLSHelper tls)
        {
            // Create a Kestrel web server, and tell it to use the Startup class
            // for the service configuration

            

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
