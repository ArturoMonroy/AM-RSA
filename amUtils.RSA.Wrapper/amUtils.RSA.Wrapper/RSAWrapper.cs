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


        //Implemente eso a modo de pasarle la instancia de Operaciones
        //Pero ya perdi mucho tiempo y aunque compila cuando exporto en Delphi
        //No logro acceder a los metodos correctamente
        //El problema claramente esta en que deberia pasar la interfaz IOperaciones
        // Dejare la implementacion
        //public static void CreaObjeto([MarshalAs(UnmanagedType.Interface)] out IOperaciones objeto)
        
        [DllExport(CallingConvention = CallingConvention.Cdecl)]
        public static void CreaObjeto([MarshalAs(UnmanagedType.Interface)] out object objeto)
        {

            objeto = null;
            try
            {

                MethodInfo methodInfo;
                methodInfo = type.GetMethod("creaObjeto");

                objeto = methodInfo.Invoke(null, null);
                
            }
            catch (Exception)
            {
                
            }            
        }

        [DllExport("Version", CallingConvention = CallingConvention.Cdecl)]
        public static void Version([MarshalAs(UnmanagedType.BStr)] out string version)
        {
            version = "2.0.0.1";
        }

        [DllExport("FirmaPEM", CallingConvention = CallingConvention.Cdecl)]
        public static int FirmaPEM(IntPtr PEM_P, IntPtr data_P, [MarshalAs(UnmanagedType.BStr)] out string signature)
        {
            string result;
            string[] a;
            int n = -1;
            MethodInfo methodInfo;
            string PEM;
            string data;

            try
            {
                PEM = Marshal.PtrToStringAuto(PEM_P);
                data = Marshal.PtrToStringAuto(data_P);

                methodInfo = type.GetMethod("FirmaPEMNTS", new Type[] { typeof(string), typeof(string) });

                result = (string)methodInfo.Invoke(null, new object[] { PEM, data });

                a = result.Split(',');
                int.TryParse(a[0], out n);
                signature = a[1];

                n = 0;
            }
            catch (Exception e)
            {
                signature = string.Format("Error no esperado [{0}]", e.Message);
            }
            
            return n;

        }

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

                methodInfo = type.GetMethod("GeneraNTS", new Type[] { typeof(string), typeof(int) });

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

                methodInfo = type.GetMethod("DeCoNTS", new Type[] { typeof(string), typeof(string), typeof(string), typeof(int), typeof(bool) });
            
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
