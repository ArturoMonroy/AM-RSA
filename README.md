> Generacion de llaves RSA tipo NET (xml), PKCS8 y PKCS1. Cifrado y Descifrado. Conversion de llave privada PKCS8 a PKCS1

> Create RSA pair for NET (xml), PKCS8 and PKCS1. Encrypt and Decrypt. Private Key PKCS8 to PKCS1

# Herramientas RSA. 
## Opcionalmente exponer los metodos en una DLL como C++ para uso universal (no solamente .Net)
# RSA Tools. 
## Optional expose those methods on DLL like C++ to use universally


## Como iniciar/ How to start

1. Descomprime BouncyCastle_Crypto.rar / Unrar BouncyCastle_Crypto.rar 
2. Ejecuta amUtils.RSA.Test, te enseñara/mostrara todo lo que necesitas saber / Execute amUtils.RSA.Test, then will show up all you need to know 

# OpenSSL
> Tambien es posible usar OpenSSL para generar llaves RSA, abajo los comandos
> OpenSSL to create RSA pair is valid, commands

`.\openssl genpkey -algorithm RSA -out RSA\llavePrivada_PKCS8_1024.pem -pkeyopt rsa_keygen_bits:1024`

`.\openssl rsa -pubout -in RSA\llavePrivada_PKCS8_1024.pem -out RSA\llavePublica_PKCS8_1024.pem`


# Opcionalmente /Optionally

## Si necesitas exportar los metodos a una DLL al estilo C++ (x32 o x64)
## If you need to export this methods to a DLL like C++ (x32 or x64)
1. Build amUtils.RSA 
2. Build amUtils.RSA.Wrapper (x86 o x64)
3. Listo/All done
`Con los pasos anteriores obtendras amUtils.RSA.dll, crypto.dll (ambos en Any CPU) y amUtils.RSA.Wrapper.dll (o amUtils.RSA.Wrapperx32.dll dependiento del build que escogas)`

`Follow the steps above you gonna get amUtils.RSA.dll, crypto.dll (both Any CPU) and amUtils.RSA.Wrapper.dll (or amUtils.RSA.Wrapperx32.dll depends of build you chose)` 


### Breve historia / Summary
` Me vi en la necesidad de usar cifrado RSA en Delphi, la forma mas optima es usando una DLL ( no encontre APIs en Delphi ).` 

` La forma mas simple es usar UnmanagedExports y exponer los metodos, sin embargo UnmanagedExports NO soporta Framework 4.6, BouncyCastle usa 4.6` 

` La solucion mas optima fue hacer un Wrapper en Framework 4.0. Cargar dinamicamente la DLL amUtils.RSA.dll ( necesita crypto.dll ) usando amUtils.RSA.Wrapper, finalmente exponer los metodos como C++ usando UnmanagedExports

```
English
```
` I needed to use RSA in Delphi, the straigth way is using DLL (not found APIs RSA in Delphi)`

` Using UnmanagedExports is the easiest way to do that, but unfortunately UnmanagedExports Does not support Framework 4.6, BouncyCastle needs 4.6`

` Then I make amtUtils.RSA.Wrapper using Framework 4.0 to load dinamycally amUtils.RSA.dll (needs cryto.dll) and then expose those methods using UnmanagedExports like C++`

## Recursos/ Sources
### Para lograr todo lo anterior use/modifique los siguiente / To get all these I use/modify next

[UnmanagedExports](https://www.nuget.org/packages/UnmanagedExports).
[stulzq](https://github.com/stulzq/RSAUtil)
[BouncyCastle](https://github.com/kerryjiang/BouncyCastle.Crypto)
