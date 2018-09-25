using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace amUtils.RSAExe
{
    class Program
    {

        static string DLL = "amUtils.RSA.dll";
        static Assembly assembly = Assembly.LoadFrom(DLL);
        static Type type = assembly.GetType("amUtils.RSA.Operaciones");
            
        static void Main(string[] args)
        {
            string llavePublica, llavePrivada, claro, cifrado, tipo;
            int longitud = 1024;
             
            tipo = "xml";
            Console.WriteLine("Generando llaves XML...");
            Genera(tipo, longitud, out llavePrivada, out llavePublica);
            Console.WriteLine(string.Format("OK\n{0}\n{1}", llavePrivada, llavePublica));
            
            Console.WriteLine("Cifrando...");
            cifrado = DeCo("TLOZ XML", tipo, llavePublica, longitud, true);
            Console.WriteLine("Descifrando...");
            claro = DeCo(cifrado, tipo, llavePrivada, longitud, false);

            Console.WriteLine( string.Format("{0} {1} {2} {3}\n", tipo, longitud, claro, cifrado) );

            tipo = "pkcs1";
            Console.WriteLine("Generando llaves PKCS1...");
            Genera(tipo, longitud, out llavePrivada, out llavePublica);
            Console.WriteLine( string.Format("OK\n{0}\n{1}", llavePrivada, llavePublica) );
            
            Console.WriteLine("Cifrando");
            cifrado = DeCo("TLOZ PKCS1", tipo, llavePublica, longitud, true);
            Console.WriteLine("Descifrando");
            claro = DeCo(cifrado, tipo, llavePrivada, longitud, false);
            Console.WriteLine(string.Format("{0} {1} {2} {3}\n", tipo, longitud, claro, cifrado));

            tipo = "pkcs8";
            Console.WriteLine("Generando llaves PKCS8...");
            Genera(tipo, longitud, out llavePrivada, out llavePublica);
            Console.WriteLine(string.Format("OK\n{0}\n{1}", llavePrivada, llavePublica));
            
            Console.WriteLine("Cifrando...");
            cifrado = DeCo("TLOZ PKCS8", tipo, llavePublica, longitud, true);
            Console.WriteLine("Descifrando...");
            claro = DeCo(cifrado, tipo, llavePrivada, longitud, false);
            Console.WriteLine(string.Format("{0} {1} {2} {3}\n", tipo, longitud, claro, cifrado));

            Console.WriteLine(string.Format("PKC8 a PKCS1 {0}", LlavePrivadaPKCS8_A_PKCS1(llavePrivada)));

            //.\openssl genpkey -algorithm RSA -out RSA\llavePrivada_PKCS8_1024.pem -pkeyopt rsa_keygen_bits:1024
            //.\openssl rsa -pubout -in RSA\llavePrivada_PKCS8_1024.pem -out RSA\llavePublica_PKCS8_1024.pem
            Console.WriteLine("Cargando llaves creadas usando OpenSSL");

            tipo = "pkcs8";
            llavePublica = System.IO.File.ReadAllText("llavePublica_PKCS8_1024.pem");
            llavePrivada = System.IO.File.ReadAllText("llavePrivada_PKCS8_1024.pem");

            Console.WriteLine("Cifrando...");
            cifrado = DeCo("RSA OpenSSL PKCS8", tipo, llavePublica, longitud, true);
            Console.WriteLine("Descifrando...");
            claro = DeCo(cifrado, tipo, llavePrivada, longitud, false);

            Console.WriteLine(claro);         
            
            Console.ReadLine();          

        }

        public static string LlavePrivadaPKCS8_A_PKCS1(string llavePrivada)
        {
            MethodInfo methodInfo;

            methodInfo = type.GetMethod("LlavePrivadaPKCS8_A_PKCS1", new Type[] { typeof(string) });

            return (string)methodInfo.Invoke(null, new object[] { llavePrivada });

        }

        public static string DeCo(string texto, string tipo, string llave, int longitud, bool encriptar)
        {
            MethodInfo methodInfo;

            methodInfo = type.GetMethod("DeCo", new Type[] { typeof(string), typeof(string), typeof(string), typeof(int), typeof(bool) });

            return (string)methodInfo.Invoke(null, new object[] { texto, tipo, llave, longitud, encriptar });

        }

        public static void Genera(string tipo, int longitud, out string llavePrivada, out string llavePublica)
        {

            MethodInfo methodInfo;

            string result;
            string[] par;

            methodInfo = type.GetMethod("Genera", new Type[] { typeof(string), typeof(int) });

            result = (string)methodInfo.Invoke(null, new object[] { tipo, longitud });
            par = result.Split(new char[] { ',' });
            llavePrivada = par[0];
            llavePublica = par[1];

        }

    }
}
