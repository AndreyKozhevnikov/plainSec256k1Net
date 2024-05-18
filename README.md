The code to calculate a public key from a private key (arrange of bytes) with the  secp256k1 elliptic curve.

### How to use

```
   byte[] intBytes = BitConverter.GetBytes(3);
   Array.Reverse(intBytes);
   byte[] privateKeyBytes = new byte[32];
   var dest = 32 - intBytes.Length;
   Array.Copy(intBytes, 0, privateKeyBytes, dest, intBytes.Length);

   var res = Sec256Calculator.GetPublicKeyNative(privateKeyBytes);
   var compressed_public_key_st = Convert.ToHexString(res).ToLower();


   Assert.AreEqual("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", compressed_public_key_st);
```
or
```
            byte[] privateKeyBytes = Convert.FromHexString("FF80A7C177E8C2444DEE3C2B5AAC6688761DDB49BCD03124F8B10541547C90EB");

            var res = Sec256Calculator.GetPublicKeyNative(privateKeyBytes);
            var compressed_public_key_st = Convert.ToHexString(res).ToLower();

            Assert.AreEqual("025e75559cc1a98348fa5f6009843891fc4b83c74eacb727cc35b092d99b31738e", compressed_public_key_st);

```

### Related projects

[AndreyKozhevnikov/net-bitcoin-address-generator](https://github.com/AndreyKozhevnikov/net-bitcoin-address-generator)  (generate Bitcoin public addresses with .NET)
[AndreyKozhevnikov/c-bitcoin-address-generator](https://github.com/AndreyKozhevnikov/c-bitcoin-address-generator) (generate Bitcoin public addresses with C++)
[AndreyKozhevnikov/Bitcoin-Address-Generator](https://github.com/AndreyKozhevnikov/Bitcoin-Address-Generator) (generate Bitcoin public addresses with Python)
[AndreyKozhevnikov/plainSec256k1Net](https://github.com/AndreyKozhevnikov/plainSec256k1Net) (.NET code to calculate a public key from a private key (arrange of bytes) with the  secp256k1 elliptic curve)

### Tips (btc)

bc1q7uas0hqke0cdp43rnh6u43d2yclhzqzkjav9cj

