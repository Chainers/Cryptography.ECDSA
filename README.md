# Cryptography.ECDSA (secp256k1 only)

This is an easy-to-use implementation of ECDSA cryptography (Elliptic Curve Digital Signature Algorithm), implemented in C#, released under the MIT license. With this library, you can quickly sign messages. 

## Features

This library provides signing based on secp256k1 algorithm wich used in the blockchains (Graphene) such as Steam and Golos (based on https://github.com/warner/python-ecdsa)
No other curves are included.

Project contain several classes and structs. Almost all of them internal (hiden) (including PrivateKey and PublicKey). 
You may use public classes Secp256K1 and Base58 for signing or make some classes as public if need

## Usage
```
//wif = it`s your privat sign key
var key = new Base58(wif);
var msg = System.Text.Encoding.UTF8.GetBytes("Hello world");
var sig = curve.Sign(msg, key);
```
