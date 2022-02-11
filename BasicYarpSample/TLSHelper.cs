using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System;
using System.Linq;
using System.IO;
using SX = System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.OpenSsl;

namespace LeiKaiFeng.X509Certificates
{
    public sealed class TLSHelper
    {
      
        SecureRandom SecureRandom { get; }

        X509Certificate CaCert { get; }

        AsymmetricKeyParameter PrivateKey { get; }


        private TLSHelper(SecureRandom secureRandom, X509Certificate caCert, AsymmetricKeyParameter privateKey)
        {
            SecureRandom = secureRandom;
            CaCert = caCert;
            PrivateKey = privateKey;
        }




        static X509Certificate AsBouncyCastleCert(SX.X509Certificate2 certificate2)
        {
            return DotNetUtilities.FromX509Certificate(certificate2);
        }

        static AsymmetricKeyParameter AsBouncyCastleKey(SX.X509Certificate2 certificate2)
        {
            var pri = SX.RSACertificateExtensions.GetRSAPrivateKey(certificate2);

            return DotNetUtilities.GetRsaKeyPair(pri).Private;
        }



        public static TLSHelper OpenCaCertFromFile(string path)
        {
            var bytes = File.ReadAllBytes(path);

            var x5092 = new SX.X509Certificate2(bytes, string.Empty, SX.X509KeyStorageFlags.Exportable);

            var cert = AsBouncyCastleCert(x5092);
           
            var key = AsBouncyCastleKey(x5092);


            return new TLSHelper(new SecureRandom(), cert, key);
        }

        public SX.X509Certificate2 AsToX509Certificate2()
        {
            return AsForm(CaCert, PrivateKey, SecureRandom);
        }

        //生成证书的序列号，随机生成
        static BigInteger GenerateSerialNumber(SecureRandom random)
        {
            return BigIntegers.CreateRandomInRange(
                    BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);
        }

        //生成RSA参数
        static AsymmetricCipherKeyPair GenerateRsaKeyPair(SecureRandom random, int keySize)
        {
            var key = new RsaKeyPairGenerator();

            key.Init(new KeyGenerationParameters(random, keySize));

            return key.GenerateKeyPair();
        }

        static ReadOnlySpan<byte> AsByteArray(X509Certificate certificate, AsymmetricKeyParameter privateKey,
            string password, SecureRandom random)
        {

            string friendlyName = certificate.SubjectDN.ToString();

            var certificateEntry = new X509CertificateEntry(certificate);

            var store = new Pkcs12Store();

            store.SetCertificateEntry(friendlyName, certificateEntry);

            store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(privateKey), new[] { certificateEntry });

            var stream = new MemoryStream();

            store.Save(stream, password.ToCharArray(), random);
            
            //stream.Position = 0;

            return stream.GetBuffer().AsSpan(0, checked((int)stream.Length));
        }

     
        static SX.X509Certificate2 AsForm(X509Certificate certificate,
            AsymmetricKeyParameter privateKey, SecureRandom random)
        {
            const string PASSWORD = "3f2b9091-3374-4eac-ab5a-37688a5a59eb";

            var buffer = AsByteArray(certificate, privateKey, PASSWORD, random);


            return new SX.X509Certificate2(buffer, PASSWORD, SX.X509KeyStorageFlags.Exportable);
        }


        static void SetDateTime(X509V3CertificateGenerator generator, int days)
        {
            var dt = DateTime.UtcNow;

            generator.SetNotBefore(dt);
            generator.SetNotAfter(dt.AddDays(days));
        }

        //设置是否是CA证书
        static void SetBasicConstraints(X509V3CertificateGenerator generator, bool ca)
        {
            generator.AddExtension(X509Extensions.BasicConstraints, false, new BasicConstraints(ca));
        }

        //设置DNS域名
        static void SetSubjectAlternativeNames(X509V3CertificateGenerator generator, string[] names)
        {
            var subjectAlternativeNames =
                names.Select((s) => new GeneralName(GeneralName.DnsName, s)).ToArray();

            var subjectAlternativeNamesExtension = new DerSequence(subjectAlternativeNames);

            generator.AddExtension(
                X509Extensions.SubjectAlternativeName, false, subjectAlternativeNamesExtension);

        }

        //证书的扩展使用方法，只能用于服务器验证
        static void SetExtendedKeyUsage(X509V3CertificateGenerator generator)
        {
            var usages = new[] { KeyPurposeID.IdKPServerAuth };
            generator.AddExtension(
                X509Extensions.ExtendedKeyUsage,
                false,
                new ExtendedKeyUsage(usages));
        }

        //设置密钥标识符
        static void SetuthorityKeyIdentifier(X509V3CertificateGenerator generator, AsymmetricKeyParameter issuerPublic)
        {
           
            var authorityKeyIdentifier = new AuthorityKeyIdentifierStructure(issuerPublic);
            generator.AddExtension(
                X509Extensions.AuthorityKeyIdentifier, false, authorityKeyIdentifier);


        }

        //设置CA的Key使用约束
        static void SetKeyUsageCA(X509V3CertificateGenerator generator)
        {
            generator.AddExtension(X509Extensions.KeyUsage, false, new KeyUsage(KeyUsage.KeyCertSign));
        }

        //设置TLS证书的Key使用约束
        static void SetKeyUsageTls(X509V3CertificateGenerator generator)
        {
            generator.AddExtension(X509Extensions.KeyUsage, false, new KeyUsage(KeyUsage.DigitalSignature));
        }

        //主题密钥标识符
        static void SetSubjectPublicKey(X509V3CertificateGenerator generator, AsymmetricKeyParameter subjectPublic)
        {
            //Subject Key Identifier
            var subjectKeyIdentifier = new SubjectKeyIdentifier(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectPublic));

            generator.AddExtension(
                X509Extensions.SubjectKeyIdentifier, false, subjectKeyIdentifier);

        }


        public static TLSHelper CreateCaCert(string name, int keySize, int days)
        {
            return CreateCaCert(name, keySize, days, new SecureRandom());
        }

        static TLSHelper CreateCaCert(string name, int keySize, int days, SecureRandom secureRandom)
        {
            var key = GenerateRsaKeyPair(secureRandom, keySize);

            var gen = new X509V3CertificateGenerator();

            var subject = new X509Name("CN=" + name);

            gen.SetIssuerDN(subject);

            gen.SetSubjectDN(subject);

            gen.SetSerialNumber(GenerateSerialNumber(secureRandom));

            SetDateTime(gen, days);

            gen.SetPublicKey(key.Public);

            SetKeyUsageCA(gen);

            SetBasicConstraints(gen, true);

            SetExtendedKeyUsage(gen);

            SetuthorityKeyIdentifier(gen, key.Public);

            SetSubjectPublicKey(gen, key.Public);

            var cert = gen.Generate(new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id, key.Private));


            return new TLSHelper(secureRandom, cert, key.Private);
        }
      

      


        static X509V3CertificateGenerator CreateTlsCertRequest(
            X509Name issuerName,
            AsymmetricKeyParameter issuerPublicKey,
            X509Name subjectName,
            AsymmetricKeyParameter subjectPublicKey,
            int days,
            string[] subjectNames,
            SecureRandom secureRandom)
        {
            var gen = new X509V3CertificateGenerator();

            gen.SetIssuerDN(issuerName);

            gen.SetSubjectDN(subjectName);

            gen.SetSerialNumber(GenerateSerialNumber(secureRandom));

            SetDateTime(gen, days);

            gen.SetPublicKey(subjectPublicKey);

            SetBasicConstraints(gen, false);

            SetExtendedKeyUsage(gen);
            
            SetuthorityKeyIdentifier(gen, issuerPublicKey);

            SetKeyUsageTls(gen);

            SetSubjectPublicKey(gen, subjectPublicKey);

            SetSubjectAlternativeNames(gen, subjectNames);

            return gen;
        }

    
        public SX.X509Certificate2 CreateTlsCert(
            string name,
            int keySize,
            int days,
            string[] subjectNames)
        {
            return CreateTlsCert(CaCert, PrivateKey, name, keySize, days, subjectNames, SecureRandom);
        }

        static SX.X509Certificate2 CreateTlsCert(
            X509Certificate caCert,
            AsymmetricKeyParameter caPrivateKey,
            string name,
            int keySize,
            int days,
            string[] subjectNames,
            SecureRandom secureRandom)
        {



            var subjectName = new X509Name($"CN=" + name);

            var subjectKey = GenerateRsaKeyPair(secureRandom, keySize);



            var certGen = CreateTlsCertRequest(
                caCert.IssuerDN,
                caCert.GetPublicKey(),
                subjectName,
                subjectKey.Public,
                days,
                subjectNames,
                secureRandom);

            var cert = certGen.Generate(new Asn1SignatureFactory(
                PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id,
                caPrivateKey));





            return AsForm(cert, subjectKey.Private, secureRandom);

        }




        
    }


   

    public static class CreatePemExtensions
    {

        static byte[] As(object obj)
        {
            MemoryStream memoryStream = new MemoryStream();
            using (TextWriter tw = new StreamWriter(memoryStream, System.Text.Encoding.ASCII))
            {
                PemWriter pw = new PemWriter(tw);

                pw.WriteObject(obj);

                tw.Flush();
            }

            return memoryStream.ToArray();
        }

        public static byte[] AsPemCert(this SX.X509Certificate2 certificate2)
        {
            return As(DotNetUtilities.FromX509Certificate(certificate2));
        }

        public static byte[] AsPemKey(this SX.X509Certificate2 certificate2)
        {
            var pri = SX.RSACertificateExtensions.GetRSAPrivateKey(certificate2);



            var keyPair = DotNetUtilities.GetRsaKeyPair(pri).Private;

            return As(keyPair);
        }
    }
}