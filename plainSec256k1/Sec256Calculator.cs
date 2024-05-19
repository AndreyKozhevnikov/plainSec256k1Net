using System.Collections;
using System.Numerics;

namespace plainSec256k1;
public class Sec256Calculator {
    public Sec256Calculator() {
        primeModulus = BigInteger.Parse("115792089237316195423570985008687907853269984665640564039457584007908834671663");
        G = new Tuple<BigInteger, BigInteger>(BigInteger.Parse("55066263022277343669578718895168534326250603453777594175500187360389116729240"), BigInteger.Parse("32670510020758816978083085130507043184471273380659243275938904335757337482424"));
    }
    //  public static BigInteger primeModulus = BigInteger.Pow(2, 256) - BigInteger.Pow(2, 32) - BigInteger.Pow(2, 9) - BigInteger.Pow(2, 8) - BigInteger.Pow(2, 7) - BigInteger.Pow(2, 6) - BigInteger.Pow(2, 4) - 1;
    public BigInteger primeModulus;
    public Tuple<BigInteger, BigInteger> G;

    public Tuple<BigInteger, BigInteger> GetPublicKeyPoint(byte[] privateKey) {
        //Array.Reverse(privateKey);

        var fullPrivateKey = new byte[33];
        fullPrivateKey[32] = 0x0;
        Array.Copy(privateKey, 0, fullPrivateKey, 0, 32);

        var k = new BigInteger(fullPrivateKey);
        var publicKeyPoint = Multiply(k, G);
        return publicKeyPoint;
    }
    public byte[] GetCompressedPublicKeyFromPoint(Tuple<BigInteger, BigInteger> publicKeyPoint) {
        var publicKeyArray = publicKeyPoint.Item1.ToByteArray();
        var compressed_public_key = new byte[33];
        if(publicKeyPoint.Item2 % 2 == 0) {
            compressed_public_key[32] = 0x02;
        } else {
            compressed_public_key[32] = 0x03;
        }
        Array.Copy(publicKeyArray, compressed_public_key, Math.Min(32, publicKeyArray.Length));
        Array.Reverse(compressed_public_key);

        return compressed_public_key;
    }
    public byte[] GetCompressedPublicKey(byte[] privateKey) {
        // generator point (the starting point on the curve used for all calculations)


        var publicKeyPoint = GetPublicKeyPoint(privateKey);

        return GetCompressedPublicKeyFromPoint(publicKeyPoint);
    }


    public BigInteger modInverse(BigInteger a, BigInteger n) {
        BigInteger i = n, v = 0, d = 1;
        if(a < 0) {
            a = MyModulus(a, n);
        }
        while(a > 0) {
            BigInteger t = i / a, x = a;
            a = MyModulus(i, x);
            i = x;
            x = d;
            d = v - t * x;
            v = x;
        }
        v = MyModulus(v, n);
        if(v < 0) v = MyModulus((v + n), n);
        return v;
    }

    public BigInteger MyModulus(BigInteger k, BigInteger m) {
        BigInteger n;
        if(k >= 0) {
            n = (k / m);
        } else {
            n = (k / m) - 1; //dirty hack. need to rewrite and/or check (upd: seems to work fine so skip so far)
        }
        BigInteger y = k - m * n;
        return y;
    }
    public Tuple<BigInteger, BigInteger> Double(Tuple<BigInteger, BigInteger> point) {

        // # slope = (3x^2 + a) / 2y    a=0

        //   '/2y' part
        var x3 = 3 * BigInteger.Pow(point.Item1, 2); //++
        var y2 = BigInteger.Multiply(point.Item2, 2); //++

        var y2mod = modInverse(y2, primeModulus);

        var r1 = x3 * y2mod;
        var slope = r1 % primeModulus;

        //# new x = slope^2 - 2x
        BigInteger x = (BigInteger.Pow(slope, 2) - (2 * point.Item1)) % primeModulus;

        //# new y = slope * (x - new x) * y
        BigInteger yT0 = (slope * (point.Item1 - x) - point.Item2);
        BigInteger y = MyModulus(yT0, primeModulus);

        //# return x, y coordinates of point
        return new Tuple<BigInteger, BigInteger>(x, y);
    }
    public Tuple<BigInteger, BigInteger> Add(Tuple<BigInteger, BigInteger> point1, Tuple<BigInteger, BigInteger> point2) {

        if(point1 == point2) {
            return Double(point1);
        }

        //# slope = (y1 - y2) / (x1 - x2)
        //  slope = ((point1[:y] - point2[:y]) * modinv(point1[:x] - point2[:x])) % $p
        var diffX = point1.Item1 - point2.Item1;
        var diffXMod = modInverse(diffX, primeModulus);
        var diffY = point1.Item2 - point2.Item2;
        var sum = diffY * diffXMod;

        //  var slope = sum % primeModulus;
        BigInteger slope = MyModulus(sum, primeModulus);

        //# new x = slope^2 - x1 - x2
        BigInteger x = MyModulus((BigInteger.Pow(slope, 2) - point1.Item1 - point2.Item1), primeModulus);

        // # new y = slope * (x1 - new x) - y1
        BigInteger y = MyModulus(((slope * (point1.Item1 - x)) - point1.Item2), primeModulus);

        return new Tuple<BigInteger, BigInteger>(x, y);
    }


    public Tuple<BigInteger, BigInteger> Multiply(BigInteger k, Tuple<BigInteger, BigInteger> point) {

        var current = point;

        var bt = k.ToByteArray();
        BitArray bitArray = new BitArray(bt);

        int i = bitArray.Length - 1;
        while(bitArray[i] == false)
            --i;

        bool[] binary = new bool[i + 1];
        bool[] bitArrayBits = new bool[bitArray.Count];
        bitArray.CopyTo(bitArrayBits, 0);

        Array.Copy(bitArrayBits, binary, i + 1);
        Array.Reverse(binary);

        // ignore first binary character  https://learnmeabitcoin.com/technical/cryptography/elliptic-curve/#multiply

        for(int j = 1; j < binary.Length; j++) {
            //# 0 = double
            current = Double(current);

            //# 1 = double and add
            if(binary[j]) {
                current = Add(current, point);
            }
        }

        return current;

    }
}

