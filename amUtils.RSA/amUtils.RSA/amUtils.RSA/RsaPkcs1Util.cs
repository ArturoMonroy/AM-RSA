using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace amUtils.RSA
{
    /// <summary>
    /// RSA pkcs1 format key helper class
    /// Author:Zhiqiang Li
    /// </summary>
    public class RsaPkcs1Util : RSAUtilBase
    {
        public RsaPkcs1Util(Encoding encoding, string publicKey, string privateKey = null, int keySize = 2048)
        {
            if (string.IsNullOrEmpty(privateKey) && string.IsNullOrEmpty(publicKey))
            {
                throw new Exception("Public and private keys must not be empty at the same time");
            }


            if (!string.IsNullOrEmpty(privateKey))
            {
                PrivateRsa = System.Security.Cryptography.RSA.Create();
                PrivateRsa.KeySize = keySize;
                var priRsap = CreateRsapFromPrivateKey(privateKey);
                PrivateRsa.ImportParameters(priRsap);

                if (string.IsNullOrEmpty(publicKey))
                {
                    PublicRsa = System.Security.Cryptography.RSA.Create();
                    PublicRsa.KeySize = keySize;
                    var pubRasp = new RSAParameters
                    {
                        Modulus = priRsap.Modulus,
                        Exponent = priRsap.Exponent
                    };
                    PublicRsa.ImportParameters(pubRasp);
                }

            }

            if (!string.IsNullOrEmpty(publicKey))
            {
                PublicRsa = System.Security.Cryptography.RSA.Create();
                PublicRsa.KeySize = keySize;
                PublicRsa.ImportParameters(CreateRsapFromPublicKey(publicKey));
            }

            DataEncoding = encoding;
           
            
        }
        /// <summary>
        /// Create an RSA parameter based on the xml format public key
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        protected sealed override RSAParameters CreateRsapFromPublicKey(string publicKey)
        {
            publicKey = RsaPemFormatHelper.PublicKeyFormat(publicKey);
            RsaKeyParameters rsaKey;
            PemReader pr = new PemReader(new StringReader(publicKey));
            var obj = pr.ReadObject();

            if (obj is RsaKeyParameters ){
                rsaKey = (RsaKeyParameters) obj;
            }else{
                throw new Exception("Public key format is incorrect");
            }

            //Does not compile on VS 2012
            //if (!(obj is RsaKeyParameters rsaKey))
            //{
            //    throw new Exception("Public key format is incorrect");
            //}
            var rsap = new RSAParameters();
            rsap.Modulus = rsaKey.Modulus.ToByteArrayUnsigned();
            rsap.Exponent = rsaKey.Exponent.ToByteArrayUnsigned();
            return rsap;
        }

        /// <summary>
        /// Create an RSA parameter based on the xml format private key
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        protected sealed override RSAParameters CreateRsapFromPrivateKey(string privateKey)
        {
            privateKey = RsaPemFormatHelper.Pkcs1PrivateKeyFormat(privateKey);
            AsymmetricCipherKeyPair asymmetricCipherKeyPair;
            PemReader pr = new PemReader(new StringReader(privateKey));
            var aObjeto = pr.ReadObject();
            if (aObjeto is AsymmetricCipherKeyPair)
            {
                asymmetricCipherKeyPair = (AsymmetricCipherKeyPair)aObjeto;
            }else {
                throw new Exception("Private key format is incorrect");
            }
            
            //Does not compile on VS 2012
            //if (!(pr.ReadObject() is AsymmetricCipherKeyPair asymmetricCipherKeyPair))
            //{
            //    throw new Exception("Private key format is incorrect");
            //}
            RsaPrivateCrtKeyParameters rsaPrivateCrtKeyParameters =
                (RsaPrivateCrtKeyParameters) PrivateKeyFactory.CreateKey(
                    PrivateKeyInfoFactory.CreatePrivateKeyInfo(asymmetricCipherKeyPair.Private));
            var rsap = new RSAParameters();
            rsap.Modulus = rsaPrivateCrtKeyParameters.Modulus.ToByteArrayUnsigned();
            rsap.Exponent = rsaPrivateCrtKeyParameters.PublicExponent.ToByteArrayUnsigned();
            rsap.P = rsaPrivateCrtKeyParameters.P.ToByteArrayUnsigned();
            rsap.Q = rsaPrivateCrtKeyParameters.Q.ToByteArrayUnsigned();
            rsap.DP = rsaPrivateCrtKeyParameters.DP.ToByteArrayUnsigned();
            rsap.DQ = rsaPrivateCrtKeyParameters.DQ.ToByteArrayUnsigned();
            rsap.InverseQ = rsaPrivateCrtKeyParameters.QInv.ToByteArrayUnsigned();
            rsap.D = rsaPrivateCrtKeyParameters.Exponent.ToByteArrayUnsigned();

            return rsap;
        }

    }
}
