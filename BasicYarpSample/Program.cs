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
using System.Threading;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Concurrent;

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

        static string GetCAPFXPath()
        {
            var path = AppDomain.CurrentDomain.BaseDirectory;

            return Path.Combine(path, "ca.pfx");
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

            var vs = new string[] { "-profile", "\"" + userPath + "\""};



            info.UseShellExecute = false;
            info.FileName = appPath;
            info.WorkingDirectory = Path.GetDirectoryName(appPath);
            info.Arguments = string.Join(" ", vs);

            Process.Start(info);


        }

        static TLSHelper CreateTLSHelper(string capem)
        {

            var capfx = GetCAPFXPath();

            if (File.Exists(capfx))
            {
                return TLSHelper.OpenCaCertFromFile(capfx);
            }
            else
            {
                var tls = TLSHelper.CreateCaCert("LEIKAIFENG CA ROOT", 2048, 300);

                var x5092 = tls.AsToX509Certificate2();

                File.WriteAllBytes(capfx, x5092.Export(X509ContentType.Pfx));

                File.WriteAllBytes(capem, x5092.AsPemCert());

                return tls;
            }
        }


        public static void Main(string[] args)
        {
            var createdNew = false;

            var mx = new Mutex(true, "{4EF719CA-CFF8-4185-BCC5-5DF1B4EFA29F}", out createdNew);

            if (!createdNew)
            {


                RunFirefox(GetFirefoxAppPath(), GetFirefoxUserFile());

                return;
            }

            var capem = GetCAPemPath();

            var tls = CreateTLSHelper(capem);


            CreateFirefoxPoliciesJsonFile(capem, GetFirefoxPath());

            CreateUserInfoFile(GetFirefoxUserFile());




            RunFirefox(GetFirefoxAppPath(), GetFirefoxUserFile());

            RunAsp(args, tls);

            
        }


        static void RunAsp(string[] args, TLSHelper tls)
        {
            // Create a Kestrel web server, and tell it to use the Startup class
            // for the service configuration



            var dic = new ConcurrentDictionary<string, X509Certificate2>();


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

                                return dic.GetOrAdd(sni, (sni) =>
                                {
                                    var tlsCert = tls.CreateTlsCert(
                                           Regex.Replace(name, @"[^A-Za-z0-9]", ""),
                                           2048,
                                           30000,
                                           new string[] { sni });

                                    return tlsCert;
                                });



                            };

                        });
                    });
                });


            });
            var myHost = myHostBuilder.Build();
            myHost.Run();
        }
    }


    sealed class SaveFileStream : Stream
    {
        readonly Stream _readStream;

        readonly Stream _saveStream;

        public SaveFileStream(Stream saveStream, Stream readStream)
        {
            _readStream = readStream;

            _saveStream = saveStream;
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
           
            await _readStream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);

            await _saveStream.WriteAsync(buffer, CancellationToken.None).ConfigureAwait(false);
 
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Console.WriteLine("ReadAsync run");

            throw new NotImplementedException();
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            Console.WriteLine("FlushAsync run");

            return Task.CompletedTask;
        }


        public override void Flush()
        {
            Console.WriteLine("Flush run");

          
        }

        protected override void Dispose(bool disposing)
        {
            Console.WriteLine("Dispose run");

            _saveStream.Close();

        }

        public override ValueTask DisposeAsync()
        {
            Console.WriteLine("DisposeAsync run");
            return default;
        }

        public override bool CanTimeout => base.CanTimeout;

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotImplementedException();

        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

      
        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotImplementedException();
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }

    }



   
    public class Startup
    {

        readonly IConfiguration _configuration;

        public Startup(IConfiguration configuration)
        {
            _configuration = configuration;
        }


        public void ConfigureServices(IServiceCollection services)
        {
            services.AddHttpForwarder();

           
        }

       
        public void Configure(IApplicationBuilder app, IHttpForwarder forwarder)
        {
           
            var httpClient = new HttpMessageInvoker(new SocketsHttpHandler()
            {
                UseProxy = false,
                AllowAutoRedirect = false,
                AutomaticDecompression = DecompressionMethods.None,
                UseCookies = false
            });

           
            var transformer = new CustomTransformer(); 
            var requestOptions = new ForwarderRequestConfig { ActivityTimeout = TimeSpan.FromSeconds(100) };

            var path = _configuration["StartPath"];
            Console.WriteLine(path);
            app.UseRouting();

            app.UseWhen(con =>
            {
                Console.WriteLine($"AAAAAAAAAAAAAAAAAAAA{con.Request.Path}");

                return con.Request.Path.StartsWithSegments(path, StringComparison.OrdinalIgnoreCase);

            }, F记录内容);

            

            app.UseEndpoints(endpoints =>
            {
                endpoints.Map("/{**catch-all}", async httpContext =>
                {
                    //Console.WriteLine($"map run{httpContext.Request.Host} {httpContext.Request.Path} {httpContext.Request.QueryString}");

                    var error = await forwarder.SendAsync(httpContext, httpContext.Request.Scheme + "://"+ httpContext.Request.Host, httpClient, requestOptions, transformer);
                  
                    if (error != ForwarderError.None)
                    {
                        var errorFeature = httpContext.Features.Get<IForwarderErrorFeature>();
                        var exception = errorFeature.Exception;
                    }
                });
            });
        }

        static Stream Create解压缩流(Stream stream, HttpResponse response)
        {


            var ce = response.Headers["Content-Encoding"];

            if (ce == "gzip")
            {
                return new GZipStream(stream, CompressionMode.Decompress);
            }
            else if(ce == "deflate")
            {
                return new DeflateStream(stream, CompressionMode.Decompress);
            }
            else if(ce == "br")
            {
                return new BrotliStream(stream, CompressionMode.Decompress);
            }
            else
            {
                Console.WriteLine($"使用了不支持的编码{ce}");

                return stream;

            }
        }


        static void F记录内容(IApplicationBuilder app)
        {
            var saveBasePath = AppDomain.CurrentDomain.BaseDirectory;

            saveBasePath = Path.Combine(saveBasePath, "File");

            Directory.CreateDirectory(saveBasePath);

            app.Use((content, next) =>
            {

                content.Request.Headers.Remove("Accept-Encoding");

                content.Request.Headers.Add("Accept-Encoding", "gzip, deflate, br");


                var fileName = Path.Combine(saveBasePath, Path.GetRandomFileName() + ".txt");

                Stream initStream = new MemoryStream();

                content.Response.Body = new SaveFileStream(initStream, content.Response.Body);

                content.Response.OnCompleted(async () =>
                {
                    initStream.Position = 0;

                    initStream = Create解压缩流(initStream, content.Response);

                    var fileStream = new FileStream(fileName, FileMode.Create, FileAccess.Write, FileShare.None, 4096, true);

                    try
                    {
                        await initStream.CopyToAsync(fileStream);
                    }
                    finally
                    {
                        fileStream.Close();
                    }

                });

                return next();
            });
        }

      
        private class CustomTransformer : HttpTransformer
        {
            
            public override async ValueTask TransformRequestAsync(HttpContext httpContext, HttpRequestMessage proxyRequest, string destinationPrefix)
            {        
                await base.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix);

                proxyRequest.Headers.Host = null;
            }
        }
    }
}
