using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;

namespace amUtils.RSA
{
    public class Operaciones
    {

        public static string Firma(string PEM, string data)
        {
            string signature;
            int n = PEMToX509.Firma(PEM, data, out signature);

            return string.Format("{0},{1}", n, signature);
        }

        public static int Firma(string PEM, string data, out string signature)
        {

            return PEMToX509.Firma(PEM, data, out signature);
        }

        public static string Genera(string tipo, int longitud){
           string llavePrivada, llavePublica= "";
           string result = "";
           
           Genera(tipo, longitud, out llavePrivada, out llavePublica);

           result = llavePrivada + ',' + llavePublica;

           return result;
            
        }
        
        public static void Genera(string tipo, int longitud, out string llavePrivada, out string llavePublica)
        {
            List<string> par;
            string test, ok;
            /*
             indice 0 llave privada
             indice 1 llave publica
             */

            switch (tipo.Trim().ToUpper())
            {
                case "XML":
                    par = RsaKeyGenerator.XmlKey(longitud);
                    par[0] += "\n\n";
                    break;

                case "PKCS1":
                    par = RsaKeyGenerator.Pkcs1Key(longitud, true);
                    break;

                case "PKCS8":
                    par = RsaKeyGenerator.Pkcs8Key(longitud, true);
                    break;

                default:
                    throw new Exception(string.Format("Genera no conoce tipo [{0}]", tipo));
            }

            llavePrivada = par[0];
            llavePublica = par[1];

            try
            {
                test = DeCo("TEST", tipo, llavePublica, longitud, true);
                ok = DeCo(test, tipo, llavePrivada, longitud, false);
            }
            catch (Exception e)
            {                
                Genera(tipo, longitud, out llavePrivada, out llavePublica);
                test = DeCo("TEST", tipo, llavePublica, longitud, true);
                ok = DeCo(test, tipo, llavePrivada, longitud, false);       
            }

        }

        public static string DeCo(string texto, string tipo, string llave, int longitud, bool encriptar)
        {
            string result = "";
            RSAEncryptionPadding padding = System.Security.Cryptography.RSAEncryptionPadding.Pkcs1;
            Encoding encoding = System.Text.Encoding.ASCII;

            switch (tipo.Trim().ToUpper())
            {
                case "XML":
                    if (encriptar)
                    {
                        RsaXmlUtil rsaXmlUtil = new RsaXmlUtil(encoding, llave, null, longitud);
                        result = rsaXmlUtil.Encrypt(texto, padding);
                    }
                    else
                    {
                        RsaXmlUtil rsaXmlUtil = new RsaXmlUtil(encoding, "", llave, longitud);
                        result = rsaXmlUtil.Decrypt(texto, padding);

                    }

                    break;

                case "PKCS1":
                    if (encriptar)
                    {
                        RsaPkcs1Util rsaPkcs1Util = new RsaPkcs1Util(encoding, llave, null, longitud);
                        result = rsaPkcs1Util.Encrypt(texto, padding);
                    }
                    else
                    {
                        RsaPkcs1Util rsaPkcs1Util = new RsaPkcs1Util(encoding, "", llave, longitud);
                        result = rsaPkcs1Util.Decrypt(texto, padding);
                    }

                    break;

                case "PKCS8":
                    if (encriptar)
                    {
                        RsaPkcs8Util rsaPkcs8Util = new RsaPkcs8Util(encoding, llave, null, longitud);
                        result = rsaPkcs8Util.Encrypt(texto, padding);
                    }
                    else
                    {
                        RsaPkcs8Util rsaPkcs8Util = new RsaPkcs8Util(encoding, "", llave, longitud);
                        result = rsaPkcs8Util.Decrypt(texto, padding);
                    }
                    break;

                default:
                    throw new Exception(string.Format("DeCo no conoce tipo [{0}]", tipo));
            }

            return result;
        }

        public static string LlavePrivadaPKCS8_A_PKCS1(string llavePrivada)
        {

            return RsaKeyConvert.PrivateKeyPkcs8ToPkcs1(llavePrivada);
        }
    }
}
