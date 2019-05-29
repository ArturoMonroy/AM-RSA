using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using amUtils.RSA;

namespace amUtilsRSA.EXE
{
    class RSAExe
    {
        static void Main(string[] args)
        {
            string texto = "";

            string llavePrivada = "";
            string llavePublica = "";
            string result = "";
            string llave = "";
            string tipo = "";
            string cmd = "";
            string operacion = "";
            int longitud = 2048;
            bool okCMD = false;

            string _AYUDA_ =
                "1.- Generador de Llaves RSA en formato XML (Net), PKCS_1 y PKCS_8. 2048 Longitud por defecto de las llaves  \n" +
                "2.- Encripta y Desencripta Paddig usado por defecto es PKCS1\n" +
                "3.- Convierte Llave Privada PKCS8 a PKCS1 (Llave publica NO necesita conversion)\n" +
                "4.- Firma usando RSA SHA256, usando un PEM, puede usarse para obtener JWT"+
                "\nEJEMPLOS DE USO\n" +
                "\n====Generar llaves RSA====\n" +
                "RSA genera <xml|PKCS1|PKCS8> [<longitud>]\n" +
                "\n====Encripta/DesEncripta====\n" +
                "RSA encripta    <texto>   <tipo> (XML|PKCS1|PKCS8) <llavePublica> [longitud]\n" +
                "RSA desencripta <cifrado> <tipo> (XML|PKCS1|PKCS8) <llavePrivada> [longitud]\n" +
                "\n====Convierte====\n" +
                "RSA PKCS8_A_PKCS1 <llavePrivadaPKCS_8>"+
                "\n====FIRMA SHA256====\n"+
                "RSA firma <PEM> (-----BEGIN RSA PRIVATE KEY-----MIICXQ .....) <data> (Base64 eyJhbGc...) "
                
                ;

            //string s;
            //for (int i = 0; i < 50; i++)
            //{
            //    Operaciones.Genera("xml", 1024, out llavePrivada, out llavePublica);
            //
            //    s=Operaciones.DeCo("Hola", "xml", llavePublica, 1024, true);
            //    s=Operaciones.DeCo(s, "xml", llavePrivada, 1024, false);
            //
            //    Operaciones.Genera("pkcs1", 1024, out llavePrivada, out llavePublica);
            //    s = Operaciones.DeCo("Hola", "pkcs1", llavePublica, 1024, true);
            //    s = Operaciones.DeCo(s, "pkcs1", llavePrivada, 1024, false);
            //
            //    Operaciones.Genera("pkcs8", 1024, out llavePrivada, out llavePublica);
            //    s = Operaciones.DeCo("Hola", "pkcs8", llavePublica, 1024, true);
            //    s = Operaciones.DeCo(s, "pkcs8", llavePrivada, 1024, false);
            //
            //}


            try
            {
                if (args.Length >= 1)
                    cmd = args[0].Trim().ToUpper();

                foreach (var item in "RSA".Split(',')){                
                    okCMD = cmd.Equals(item);

                    if (okCMD) 
                        break;
                }

                if (! okCMD){
                    System.Console.WriteLine(_AYUDA_);
                    return;
                }

                if (args.Length >= 2)
                    operacion = args[1].Trim().ToUpper();
                
                string data;
                
                switch (operacion)
                {
                    case "GENERA":
                        tipo = args[2];
                        if (args.Length >= 4)
                            int.TryParse(args[3], out longitud);

                        Operaciones.Genera(tipo, longitud, out llavePrivada, out llavePublica);
                        result = llavePrivada + llavePublica;
                        break;

                    case "ENCRIPTA":
                    case "DESENCRIPTA":
                        texto = args[2];
                        tipo = args[3];
                        llave = args[4];

                        if (args.Length >= 6)
                            int.TryParse(args[5], out longitud);

                        result = Operaciones.DeCo(texto, tipo, llave, longitud, operacion.Equals("ENCRIPTA"));

                        break;

                    case "PKCS8_A_PKCS1":
                        llave = args[2];
                        result = Operaciones.LlavePrivadaPKCS8_A_PKCS1(llave);
                        break;

                    case "FIRMA": 
                        string pem = args[2];
                        data = args[3];
                        
                        string signature;

                        if ( PEMToX509.Firma( pem, data, out signature ) > 0 )
                            System.Console.WriteLine( string.Format("OK \n {0}", signature) );
                        else
                            System.Console.WriteLine(string.Format("Error \n {0}", signature));
                                                                        
                        break;
                    default:
                        System.Console.WriteLine(_AYUDA_);
                        break;

                }

                Console.WriteLine(result);
            }
            catch (Exception e)
            {
                Console.WriteLine(string.Format("Error no esperado. Error [{0}]\n {1} ", e.ToString(), _AYUDA_));
            }

        }
    }
}
