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
using Yarp.ReverseProxy.Transforms;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using System.Net.Http;
using Yarp.ReverseProxy.Forwarder;
using System.Net;

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

            var vs = new string[] { "-profile", "\"" + userPath + "\"", "-start-debugger-server" };



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


    /// <summary>
    /// ASP.NET Core pipeline initialization showing how to use IHttpForwarder to directly handle forwarding requests.
    /// With this approach you are responsible for destination discovery, load balancing, and related concerns.
    /// </summary>
    public class Startup
    {
        /// <summary>
        /// This method gets called by the runtime. Use this method to add services to the container.
        /// </summary>
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddHttpForwarder();
        }

        /// <summary>
        /// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        /// </summary>
        public void Configure(IApplicationBuilder app, IHttpForwarder forwarder)
        {
            // Configure our own HttpMessageInvoker for outbound calls for proxy operations
            var httpClient = new HttpMessageInvoker(new SocketsHttpHandler()
            {
                UseProxy = false,
                AllowAutoRedirect = false,
                AutomaticDecompression = DecompressionMethods.None,
                UseCookies = false
            });

            // Setup our own request transform class
            var transformer = new CustomTransformer(); // or HttpTransformer.Default;
            var requestOptions = new ForwarderRequestConfig { ActivityTimeout = TimeSpan.FromSeconds(100) };

            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                
                // When using IHttpForwarder for direct forwarding you are responsible for routing, destination discovery, load balancing, affinity, etc..
                // For an alternate example that includes those features see BasicYarpSample.
                endpoints.Map("/{**catch-all}", async httpContext =>
                {
                    Console.WriteLine($"map run{httpContext.Request.Host} {httpContext.Request.Path} {httpContext.Request.QueryString}");

                    var error = await forwarder.SendAsync(httpContext, httpContext.Request.Scheme + "://"+ httpContext.Request.Host, httpClient, requestOptions, transformer);
                    // Check if the proxy operation was successful
                    if (error != ForwarderError.None)
                    {
                        var errorFeature = httpContext.Features.Get<IForwarderErrorFeature>();
                        var exception = errorFeature.Exception;
                    }
                });
            });
        }

        /// <summary>
        /// Custom request transformation
        /// </summary>
        private class CustomTransformer : HttpTransformer
        {
            /// <summary>
            /// A callback that is invoked prior to sending the proxied request. All HttpRequestMessage
            /// fields are initialized except RequestUri, which will be initialized after the
            /// callback if no value is provided. The string parameter represents the destination
            /// URI prefix that should be used when constructing the RequestUri. The headers
            /// are copied by the base implementation, excluding some protocol headers like HTTP/2
            /// pseudo headers (":authority").
            /// </summary>
            /// <param name="httpContext">The incoming request.</param>
            /// <param name="proxyRequest">The outgoing proxy request.</param>
            /// <param name="destinationPrefix">The uri prefix for the selected destination server which can be used to create
            /// the RequestUri.</param>
            public override async ValueTask TransformRequestAsync(HttpContext httpContext, HttpRequestMessage proxyRequest, string destinationPrefix)
            {
                

                // Copy all request headers
                await base.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix);


                // Assign the custom uri. Be careful about extra slashes when concatenating here. RequestUtilities.MakeDestinationAddress is a safe default.
                //proxyRequest.RequestUri = RequestUtilities.MakeDestinationAddress("https://"+ httpContext.Request.Host, httpContext.Request.Path, httpContext.Request.QueryString);

                // Suppress the original request header, use the one from the destination Uri.
                proxyRequest.Headers.Host = null;
            }
        }
    }
}
