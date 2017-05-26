# Cryptography.ECDSA (secp256k1 only)

This is an easy-to-use implementation of ECDSA cryptography (Elliptic Curve Digital Signature Algorithm), implemented in C#, released under the MIT license. With this library, you can quickly sign transactions. 

## Features

This library implements transaction signing based on secp256k1 algorithm which is used in Graphene-based blockchains such as Steem and Golos. The library is based on https://github.com/warner/python-ecdsa
No other curves are included.

The project contains several classes and structs. Almost all of them are internal (hidden), including PrivateKey and PublicKey. 
You may use public classes Secp256K1 and Base58 for signing or make some other classes public if need.

## Usage
```
//wif = it`s your privat sign key
var key = new Base58(wif);
var msg = System.Text.Encoding.UTF8.GetBytes("Hello world");
var sig = curve.Sign(msg, key);
```
