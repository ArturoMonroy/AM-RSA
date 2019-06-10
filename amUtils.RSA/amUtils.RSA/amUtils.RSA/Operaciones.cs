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

    //Crea una interfaz
    //La finalidad es que la libreria sea SAFE-THREAD
    //Obtienes un objeto y accedes a sus metodos
    [ComVisible(true)]
    [Guid("547B3FD6-38A0-4C13-9E6F-6221B7F83826"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IOperaciones
    {
        int FirmaPEM(string PEM, string data, out string signature);

        void Genera(string tipo, int longitud, out string llavePrivada, out string llavePublica);

        string DeCo(string texto, string tipo, string llave, int longitud, bool encriptar);
    }

    //Los metodos estaticos con NTS indican NO-THREAD-SAFE
    //Dejo los metodos estaticos a modo de retrocompatibilidad
    public class Operaciones : IOperaciones
    {

        public static IOperaciones creaObjeto()
        {
            return new Operaciones();
        }

        public int FirmaPEM(string PEM, string data, out string signature){
            int result = -1;
            signature = "";
            try
            {

                result = PEMToX509.Firma(PEM, data, out signature);
            }
            catch (Exception e)
            {
                signature = string.Format("Error no esperado el ejecutar 'FirmaPEM'. Error [{0}]", e.Message);
                
            }

            return result;

        }

        public void Genera(string tipo, int longitud, out string llavePrivada, out string llavePublica){
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

        public string DeCo(string texto, string tipo, string llave, int longitud, bool encriptar){
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

        #region metodos estaticos

        public static int FirmaNTS(string PEM, string data, out string signature)
        {

            var a = new Operaciones();
            return a.FirmaPEM(PEM, data, out signature);
        }
   
        public static void GeneraNTS(string tipo, int longitud, out string llavePrivada, out string llavePublica)
        {

            var a = new Operaciones();
            a.Genera(tipo, longitud, out llavePrivada, out llavePublica);

        }

        public static string DeCoNTS(string texto, string tipo, string llave, int longitud, bool encriptar)
        {

            var a = new Operaciones();
            return a.DeCo(texto, tipo, llave, longitud, encriptar);

        }

        public static string GeneraNTS(string tipo, int longitud)
        {
            string llavePrivada, llavePublica= "";
            string result = "";
               
            GeneraNTS(tipo, longitud, out llavePrivada, out llavePublica);
            
            result = llavePrivada + ',' + llavePublica;
            
            return result;
                
        }
                
        public static string FirmaPEMNTS(string PEM, string data)
        {
            string signature;
            int n = PEMToX509.Firma(PEM, data, out signature);
            
            return string.Format("{0},{1}", n, signature);
        }

        public static string LlavePrivadaPKCS8_A_PKCS1(string llavePrivada)
        {

            return RsaKeyConvert.PrivateKeyPkcs8ToPkcs1(llavePrivada);
        }

        #endregion
  
    }
}
