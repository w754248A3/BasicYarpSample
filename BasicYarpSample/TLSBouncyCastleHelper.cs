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
    public static class TLSBouncyCastleHelper
    {
        static readonly SecureRandom Random = new SecureRandom();

        static BigInteger GenerateSerialNumber(SecureRandom random)
        {
            return BigIntegers.CreateRandomInRange(
                    BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
        }


        static AsymmetricCipherKeyPair GenerateRsaKeyPair(SecureRandom random, int keySize)
        {
            var key = new RsaKeyPairGenerator();

            key.Init(new KeyGenerationParameters(random, keySize));

            return key.GenerateKeyPair();
        }

        static byte[] AsByteArray(X509Certificate certificate, AsymmetricCipherKeyPair key,
            string password, SecureRandom random)
        {

            string friendlyName = certificate.SubjectDN.ToString();

            var certificateEntry = new X509CertificateEntry(certificate);

            var store = new Pkcs12Store();

            store.SetCertificateEntry(friendlyName, certificateEntry);

            store.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(key.Private), new[] { certificateEntry });

            var stream = new MemoryStream();

            store.Save(stream, password.ToCharArray(), random);
            
            stream.Position = 0;
            
            return stream.ToArray();
        }

        static SX.X509Certificate2 AsForm(X509Certificate certificate,
            AsymmetricCipherKeyPair key, SecureRandom random)
        {
            const string S = "3f2b9091-3374-4eac-ab5a-37688a5a59eb";

            var buffer = AsByteArray(certificate, key, S, random);


            return new SX.X509Certificate2(buffer, S, SX.X509KeyStorageFlags.Exportable);
        }


        static void SetDateTime(X509V3CertificateGenerator generator, int days)
        {
            generator.SetNotBefore(DateTime.UtcNow);
            generator.SetNotAfter(DateTime.UtcNow.AddDays(days));
        }

        static void SetBasicConstraints(X509V3CertificateGenerator generator, bool ca)
        {
            generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(ca));
        }

        static void SetSubjectAlternativeNames(X509V3CertificateGenerator generator, string[] names)
        {
            var subjectAlternativeNames =
                names.Select((s) => new GeneralName(GeneralName.DnsName, s)).ToArray();

            var subjectAlternativeNamesExtension = new DerSequence(subjectAlternativeNames);

            generator.AddExtension(
                X509Extensions.SubjectAlternativeName, false, subjectAlternativeNamesExtension);

        }

        static void SetExtendedKeyUsage(X509V3CertificateGenerator generator)
        {
            var usages = new[] { KeyPurposeID.IdKPServerAuth };
            generator.AddExtension(
                X509Extensions.ExtendedKeyUsage,
                false,
                new ExtendedKeyUsage(usages));
        }

        static void SetuthorityKeyIdentifier(X509V3CertificateGenerator generator, AsymmetricKeyParameter issuerPublic)
        {
            //Authority Key Identifier
            var authorityKeyIdentifier = new AuthorityKeyIdentifierStructure(issuerPublic);
            generator.AddExtension(
                X509Extensions.AuthorityKeyIdentifier, false, authorityKeyIdentifier);


        }

        static void SetKeyUsageCA(X509V3CertificateGenerator generator)
        {
            generator.AddExtension(X509Extensions.KeyUsage, false, new KeyUsage(KeyUsage.KeyCertSign));
        }

        static void SetKeyUsageTls(X509V3CertificateGenerator generator)
        {
            generator.AddExtension(X509Extensions.KeyUsage, false, new KeyUsage(KeyUsage.DigitalSignature));
        }

        static void SetSubjectPublicKey(X509V3CertificateGenerator generator, AsymmetricKeyParameter subjectPublic)
        {
            //Subject Key Identifier
            var subjectKeyIdentifier = new SubjectKeyIdentifier(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectPublic));

            generator.AddExtension(
                X509Extensions.SubjectKeyIdentifier, false, subjectKeyIdentifier);

        }

        public static CaCert GenerateCA(
            string name,
            int keySize,
            int days)
        {
            var key = GenerateRsaKeyPair(Random, keySize);

            var cert = new X509V3CertificateGenerator();

            var subject = new X509Name($"CN={name}");

            

            cert.SetIssuerDN(subject);

            cert.SetSubjectDN(subject);

            cert.SetSerialNumber(GenerateSerialNumber(Random));

            SetDateTime(cert, days);

            cert.SetPublicKey(key.Public);

            SetKeyUsageCA(cert);

            SetBasicConstraints(cert, true);

            SetExtendedKeyUsage(cert);

            SetuthorityKeyIdentifier(cert, key.Public);

            SetSubjectPublicKey(cert, key.Public);

            var x509 = cert.Generate(new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id, key.Private));

            return new CaCert(AsForm(x509, key, Random));

        }




        static X509V3CertificateGenerator GenerateTls(
            X509Name issuerName,
            AsymmetricKeyParameter issuerPublicKey,
            X509Name subjectName,
            AsymmetricKeyParameter subjectPublicKey,
            int days,
            string[] subjectNames
            )
        {
            var cert = new X509V3CertificateGenerator();

            cert.SetIssuerDN(issuerName);

            cert.SetSubjectDN(subjectName);

            cert.SetSerialNumber(GenerateSerialNumber(Random));

            SetDateTime(cert, days);

            cert.SetPublicKey(subjectPublicKey);

            SetBasicConstraints(cert, false);

            SetExtendedKeyUsage(cert);
            
            SetuthorityKeyIdentifier(cert, issuerPublicKey);

            SetKeyUsageTls(cert);

            SetSubjectPublicKey(cert, subjectPublicKey);

            SetSubjectAlternativeNames(cert, subjectNames);


            return cert;
        }

    
        internal static SX.X509Certificate2 GenerateTls(
            X509Certificate caCert,
            AsymmetricKeyParameter caPrivateKey,
            string name,
            int keySize,
            int days,
            string[] subjectNames)
        {

            

            var subjectName = new X509Name($"CN={name}");

            var subjectKey = GenerateRsaKeyPair(Random, keySize);



            var certGen = GenerateTls(
                caCert.IssuerDN,
                caCert.GetPublicKey(),
                subjectName,
                subjectKey.Public,
                days,
                subjectNames);

            var x509 = certGen.Generate(new Asn1SignatureFactory(
                PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id,
                caPrivateKey));





            return AsForm(x509, subjectKey, Random);

        }




        
    }


    public sealed class CreateTls
    {
        readonly X509Certificate _cert;

        readonly AsymmetricKeyParameter _privateKey;


        static X509Certificate AsBouncyCastleCert(SX.X509Certificate2 certificate2)
        {
            return DotNetUtilities.FromX509Certificate(certificate2);
        }

        static AsymmetricKeyParameter AsBouncyCastleKey(SX.X509Certificate2 certificate2)
        {
            var pri = SX.RSACertificateExtensions.GetRSAPrivateKey(certificate2);

            return DotNetUtilities.GetRsaKeyPair(pri).Private;
        }



        internal CreateTls(SX.X509Certificate2 certificate2)
        {
            _cert = AsBouncyCastleCert(certificate2);

            _privateKey = AsBouncyCastleKey(certificate2);

        }



        public SX.X509Certificate2 Create(
            string name,
            int keySize,
            int days,
            string[] subjectNames)
        {
            return TLSBouncyCastleHelper.GenerateTls(_cert, _privateKey, name, keySize, days, subjectNames);
        }
    }

    public sealed class CaCert
    {
        readonly SX.X509Certificate2 _cert;

        internal CaCert(SX.X509Certificate2 cert)
        {
            _cert = cert;
        }


        public static CaCert CreateFromFile(string path)
        {
            var bytes = File.ReadAllBytes(path);

            return new CaCert(new SX.X509Certificate2(bytes, string.Empty, SX.X509KeyStorageFlags.Exportable));
        }

        public SX.X509Certificate2 X509Certificate2()
        {
            var bytes = _cert.Export(SX.X509ContentType.Pfx);


            return new SX.X509Certificate2(bytes, string.Empty, SX.X509KeyStorageFlags.Exportable);
        }


        public CreateTls CreateTls()
        {
            return new CreateTls(this.X509Certificate2());
        }

        public void SavePfx(string path)
        {
            var bytes = _cert.Export(SX.X509ContentType.Pfx);

            File.WriteAllBytes(path, bytes);


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