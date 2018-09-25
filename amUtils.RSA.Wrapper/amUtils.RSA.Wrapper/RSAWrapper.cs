using RGiesecke.DllExport;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace amUtils.RSA.DLL
{
    public class RSAWrapper
    {

            
        static string DLL = "amUtils.RSA.dll";
        static Assembly assembly =  Assembly.LoadFrom(DLL);
        static Type type = assembly.GetType("amUtils.RSA.Operaciones");
        
        
        string _AYUDA_ =
            "1.- Generador de Llaves RSA en formato XML (Net), PKCS_1 y PKCS_8. 2048 Longitud por defecto de las llaves  \n" +
            "2.- Encripta y Desencripta Paddig usado por defecto es PKCS1\n" +
            "3.- Convierte Llave Privada PKCS8 a PKCS1 (Llave publica NO necesita conversion)\n" +
            "\nEJEMPLOS DE USO\n" +
            "\n====Generar llaves RSA====\n" +
            "RSA genera <xml|PKCS1|PKCS8> [<longitud>]\n" +
            "\n====Encripta/DesEncripta====\n" +
            "RSA encripta    <texto>   <tipo> (XML|PKCS1|PKCS8) <llavePublica> [longitud]\n" +
            "RSA desencripta <cifrado> <tipo> (XML|PKCS1|PKCS8) <llavePrivada> [longitud]\n" +
            "\n====Convierte====\n" +
            "RSA PKCS8_A_PKCS1 <llavePrivadaPKCS_8>";

        [DllExport("Genera", CallingConvention = CallingConvention.Cdecl)]
        public static int Genera(IntPtr tipo_P, int longitud, [MarshalAs(UnmanagedType.BStr)] out string llavePrivada, [MarshalAs(UnmanagedType.BStr)] out string llavePublica)
        {
            string tipo = "";
            string result;
            string[] par;
            int ok = -1;
            llavePrivada = "";
            llavePublica = "";
            try 
	        {	        
    		    tipo = Marshal.PtrToStringAuto(tipo_P);
            
                MethodInfo methodInfo;
                            
                methodInfo = type.GetMethod("Genera", new Type[] { typeof(string), typeof(int) });

                result = (string)methodInfo.Invoke(null, new object[] { tipo, longitud });

                par = result.Split( new char[]{','});

                llavePrivada = par[0];
                llavePublica = par[1];
                                
                ok = 0;
	        }
	        catch (Exception e)
	        {
                llavePrivada = e.Message;
                llavePublica = e.InnerException.Message;
            }                              

            return ok;
        }

        [DllExport("DeCo", CallingConvention = CallingConvention.Cdecl)]
        public static int DeCo(IntPtr texto_P, IntPtr tipo_P, IntPtr llave_P, int longitud, int _encriptar, [MarshalAs(UnmanagedType.BStr)] out string result)
        {

            result = "";
            int ok = -1;
            string texto = "";
            string tipo = "";
            string llave = "";
            bool encriptar = _encriptar == 0;
            MethodInfo methodInfo;            
            try
            {
                texto = Marshal.PtrToStringAuto(texto_P);
                tipo = Marshal.PtrToStringAuto(tipo_P);
                llave = Marshal.PtrToStringAuto(llave_P);

                methodInfo = type.GetMethod("DeCo", new Type[] { typeof(string), typeof(string), typeof(string), typeof(int), typeof(bool) });
            
                result = (string)methodInfo.Invoke(null, new object[] { texto, tipo, llave, longitud, encriptar });

                ok = 0;                    
            }
            catch (Exception e)
            {
                result = string.Format("Error [{0}:{1}]", e.Message, e.InnerException.Message);                                        
            }                              

            return ok;

        }


        [DllExport("LlavePrivadaPKCS8_A_PKCS1", CallingConvention = CallingConvention.Cdecl)]
        public static int LlavePrivadaPKCS8_A_PKCS1(IntPtr llavePrivada_P , [MarshalAs(UnmanagedType.BStr)] out string result)
        {
            int ok = -1;
            string llavePrivada;
            result = "";
            try
            {
                MethodInfo methodInfo;

                llavePrivada = Marshal.PtrToStringAuto(llavePrivada_P);

                methodInfo = type.GetMethod("LlavePrivadaPKCS8_A_PKCS1", new Type[] { typeof(string) });

                result  = (string)methodInfo.Invoke(null, new object[] { llavePrivada });

                ok = 0;
            }
            catch (Exception e)
            {
                result = string.Format("{0}:{1}", e.Message, e.InnerException.Message);                
            }

            return ok;            

        }
    
    }
}
