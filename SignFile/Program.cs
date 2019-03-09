using EU.Europa.EC.Markt.Dss;
using EU.Europa.EC.Markt.Dss.Signature;
using EU.Europa.EC.Markt.Dss.Signature.Cades;
using EU.Europa.EC.Markt.Dss.Signature.Token;
using System;
using System.Linq;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace SignFile
{
    class Program
    {
        static void Main(string[] args)
        {
            string path = @"D:\Temp\FattEle\2019\2019-03(9231)\IT00141470351_defox.xml";
            var card = SelectCert(StoreName.My, StoreLocation.CurrentUser, "", "");
            SignP7M(card, path);
        }


        public static X509Certificate2 SelectCert(StoreName store, StoreLocation location, string windowTitle, string windowMsg)
        {

            X509Certificate2 certSelected = null;
            X509Store x509Store = new X509Store(store, location);
            x509Store.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection col = x509Store.Certificates;
            X509Certificate2Collection sel = X509Certificate2UI.SelectFromCollection(col, windowTitle, windowMsg, X509SelectionFlag.SingleSelection);

            if (sel.Count > 0)
            {
                X509Certificate2Enumerator en = sel.GetEnumerator();
                en.MoveNext();
                certSelected = en.Current;
            }

            x509Store.Close();

            return certSelected;
        }

        private static void SignP7M(X509Certificate2 card, string sourcepath)
        {
            var service = new CAdESService();

            // Creation of MS CAPI signature token
            var token = new MSCAPISignatureToken { Cert = card };

            var parameters = new SignatureParameters
            {
                SignatureAlgorithm = SignatureAlgorithm.RSA,
                SignatureFormat = SignatureFormat.CAdES_BES,
                DigestAlgorithm = DigestAlgorithm.SHA256,
                SignaturePackaging = SignaturePackaging.ENVELOPING,
                SigningCertificate = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(token.Cert),
                SigningDate = DateTime.UtcNow
            };

            var toBeSigned = new FileDocument(sourcepath);

            var iStream = service.ToBeSigned(toBeSigned, parameters);

            var signatureValue = token.Sign(iStream, parameters.DigestAlgorithm, token.GetKeys()[0]);

            var signedDocument = service.SignDocument(toBeSigned, parameters, signatureValue);

            var dest = sourcepath + ".p7m";
            if (File.Exists(dest)) File.Delete(dest);
            var fout = File.OpenWrite(dest);
            signedDocument.OpenStream().CopyTo(fout);
            fout.Close();
        }
    }
}
