using System;
using System.Diagnostics;
using NUnit.Framework;

namespace Cryptography.ECDSA.CLI.Tests
{
    [TestFixture]
    public class Secp256k1ManagerTest
    {
        [Test]
        public void Sha256Test()
        {
            var sw1 = new Stopwatch();
            var sw2 = new Stopwatch();

            var rand = new Random();
            for (int i = 0; i < 10000; i++)
            {
                var buf = new byte[rand.Next(1, 1000)];
                rand.NextBytes(buf);

                sw1.Start();
                var rez2 = Proxy.GetMessageHash(buf);
                sw1.Stop();

                sw2.Start();
                var rez1 = Secp256k1Manager.GetMessageHash(buf);
                sw2.Stop();

                Assert.IsTrue(rez1.Length == rez2.Length);
                for (var j = 0; j < rez1.Length; j++)
                {
                    Assert.IsTrue(rez1[j].Equals(rez2[j]), $"{buf.Length}");
                }
            }

            Console.WriteLine($"Proxy time {sw1.ElapsedTicks} / Secp256k1Manager time {sw2.ElapsedTicks}");
        }

        [Test]
        public void SignCompressedCompactTest()
        {
            var sw1 = new Stopwatch();
            var sw2 = new Stopwatch();
            var rand = new Random();
            byte[] msg;
            for (int i = 1; i < 1000; i++)
            {
                msg = new byte[i];
                rand.NextBytes(msg);
                var hex = Base58.GetBytes(TestWif);

                var hash = Secp256k1Manager.GetMessageHash(msg);

                sw1.Start();
                var signature1 = Proxy.SignCompressedCompact(hash, hex);
                sw1.Stop();

                sw2.Start();
                var signature2 = Secp256k1Manager.SignCompressedCompact(hash, hex);
                sw2.Stop();

                Assert.IsTrue(signature1.Length == 65);
                Assert.IsTrue(signature2.Length == 65);
                Assert.IsTrue(Secp256k1Manager.IsCanonical(signature2, 1));
                if (Secp256k1Manager.IsCanonical(signature1, 1))
                {
                    for (int j = 0; j < signature1.Length; j++)
                    {
                        Assert.IsTrue(signature1[j] == signature2[j]);
                    }
                }
                else
                {
                    Console.WriteLine($"signature1 not canonical - skip [{i}]");
                }
            }

            Console.WriteLine($"Proxy time {sw1.ElapsedTicks} / Secp256k1Manager time {sw2.ElapsedTicks}");
        }

        protected const string TestWif = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP78zkvFD3";

        [Test]
        [TestCase("Hello world", "1fa6bae619f0a293190572523c7fa0f9274e9a1fbb19053b3f0dd7346ccdf0f08e78c66c23021023159d54bac0a0b913ede5bd4d4a28446039559dcf802f4aefff")]
        public void SigningKeyTest(string text, string sig)
        {
            var msg = System.Text.Encoding.UTF8.GetBytes(text);
            var hex = Base58.GetBytes(TestWif);
            var sha256 = Proxy.GetMessageHash(msg);
            var signature = Proxy.SignCompressedCompact(sha256, hex);
            Assert.IsTrue(signature.Length == 65);

            var sRez = Hex.ToString(signature);
            Assert.IsTrue(sig.Equals(sRez), $"Expected:{sig} but was {sRez}");
        }
    }
}
