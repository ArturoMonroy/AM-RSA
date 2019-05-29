using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

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
             
            ///////// JWT
            string header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
            
            string payload = "{\"iss\":\"usuario@dominio.com\",\"scope\":\"https:\\/\\/www.googleapis.com\\/auth\\/rcsbusinessmessaging\",\"aud\":\"https:\\/\\/www.googleapis.com\\/oauth2\\/v4\\/token\",\"exp\":1557338845,\"iat\":1557335245}";

            byte[] a = System.Text.Encoding.Default.GetBytes(header);
            
            byte[] b = System.Text.Encoding.Default.GetBytes(payload);

            byte[] _bytes = new byte[a.Length + b.Length];
            

            for (int i = 0; i < a.Length; i++)
                _bytes[i] = a[i];

            for (int j = 0; j < b.Length; j++)
                _bytes[a.Length + j] = b[j];
            
            //Primer paso
            string data = System.Convert.ToBase64String(a) + '.' + System.Convert.ToBase64String(b);           
            string signature;
            string PEM = 
            "-----BEGIN RSA PRIVATE KEY-----"+
            "MIICXQIBAAKBgQDymMsf+68EERSkXO7lwucBa5Ibw+74z+dL/yYWsHxsl+j9E3ZK"+
            "5hQ9riiDxscTd+Jm6aqYF5Dobsk+VWoz7Ma+4iLvHiLevefRxlq7Fpe70vRZeNR5"+
            "Z+9cLaak4C4/FYrUoOrMjfHxX0Ihmc5M+Tjy4brxpktCTRRm73CyMxT7twIDAQAB"+
            "AoGBAOXc8rJWVqmiyY1HZTEdMKb+1w0p5Leqvr0agGuFRA/dDG0nULF9OfaLm2Xp"+
            "Jd4DfOkIRJUh1zL1Lge7BQs4McL529nbKirlstUDvR+dRYoyhCNCnVNqKgU/P+Ed"+
            "1wEOhVxOLKfcv847huDzzBU7ZL8E3QEQUd9t3CLj3Ov/c2C5AkEA+ks6fX0GXWht"+
            "D6IHW+XBEW4txkfm2WWI64RG8Y0avjg9P1vhw/APlCuZPRmsXQ6S9/wKJt/iy0ah"+
            "eJVJ3f1/3QJBAPggpLsU7H/0PKCmC8HUrnWG7ANIiZJYib5LJWAnCzpxNNMNmY5Z"+
            "0Ak18/ia4bloNz/g9QXIa7kuG9+lSGF+uqMCQBfcpC7ihIDTO9KJt/ni5Y0r2+FT"+
            "aYbAT1Vkvv64XRxVcEFiGRv8/v85SNqyX+RfR1OtC6q5HX4TtcExOmGXkWECQQCd"+
            "lW3JexJweRcAGDSjV4WtEpFVzH3CugRRHLySAnn5FeismZiKdbPQBbn6i7ML44oj"+
            "QaWblJwFsaj2Mqxzbt7tAkB2dxlU+ABHDJ2wvGzECecYPvDeIIcuN1VyZvnYcPek"+
            "uehkYsNKd45pNxZr0ZZN1UlVht7kBZWX/+Ij2ezShYDA"+
            "-----END RSA PRIVATE KEY-----";

            Console.WriteLine("FIRMA (JWT)...");
            Firma(PEM, data, out signature);
            Console.WriteLine( signature );
                        
            /////////// FIN JWT

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
       
       public static int Firma(string PEM, string data, out string signature)
       {
           string result;
           string [] a;
           int n  = -1;
           MethodInfo methodInfo;

           methodInfo = type.GetMethod("Firma", new Type[] { typeof(string) , typeof(string) });

           result =  (string)methodInfo.Invoke(null, new object[] { PEM, data });

           a = result.Split(',');
           int.TryParse(a[0], out n);
           signature = a[1];
                      
           return n;

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
