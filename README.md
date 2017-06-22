# Cryptography.ECDSA (secp256k1 only)

This is an easy-to-use implementation of ECDSA cryptography (Elliptic Curve Digital Signature Algorithm), implemented in C#, released under the MIT license. With this library, you can quickly sign transactions. 

## V2.0

To increase the performance, the C# implementation has been replaced by C implementation (https://github.com/bitcoin-core/secp256k1). 
Performance has increased in x3 times for cold start (init wrapper) and up to x100-x300 with repeated calls. 
The difference in numbers is due to differences in the implementation of test methods. 
Time was measured by VisualStudio-Profile-Tracing

### References
Secp256k1.NET - C++/cli glue for https://github.com/bitcoin-core/secp256k1 - to build/update the project you need to download sources to folder ..\Sources\sipa_secp256k1\ and rebuild. Assembly will be placed in \References\Secp256k1\ (x64/x86 versions).

Cryptography.ECDSA.CLI - C# SharedProject wrap Secp256k1.NET.x86.dll / Secp256k1.NET.x64.dll and contain some addition code

### Features
* Sign (byte[71])    
* SignCompact (byte[64])
* GetPublicKey
* Base58.GetBytes
* GetMessageHash - (use sha256) (byte[32])

### Usage
```
//wif = it`s your privat sign key
var msg = System.Text.Encoding.UTF8.GetBytes(text);
var hex = Base58.GetBytes(wif);
var digest = Proxy.GetMessageHash(msg);
int recId;
var signature = Proxy.SignCompact(digest, hex, out recId);
Assert.IsTrue(signature.Length == 64);

var sRez = Hex.ToString(Hex.Join(new[] { (byte)(recId + 4 + 27) }, signature));
```



## V1.0
### Features

This library implements transaction signing based on secp256k1 algorithm which is used in Graphene-based blockchains such as Steem and Golos. The library is based on https://github.com/warner/python-ecdsa
No other curves are included.

The project contains several classes and structs. Almost all of them are internal (hidden), including PrivateKey and PublicKey. 
You may use public classes Secp256K1 and Base58 for signing or make some other classes public if need.

### Usage
```
//wif = it`s your privat sign key
var key = new Base58(wif);
var msg = System.Text.Encoding.UTF8.GetBytes("Hello world");
var sig = curve.Sign(msg, key);
```
