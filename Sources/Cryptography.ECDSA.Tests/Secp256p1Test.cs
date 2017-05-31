using Cryptography.ECDSA.Curves;
using NUnit.Framework;

namespace Cryptography.ECDSA.Tests
{
    [TestFixture]
    public class Secp256p1Test
    {
        protected const string TestWif = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP78zkvFD3";
        readonly Secp256K1 _secp256H1 = new Secp256K1();

        [Test]
        [TestCase("Hello world", "1f3e46406bfc338910b5e500ed8ab8fbd7367ccbfc0727f3fd380605b0a0c634835568d8e7036fe3c775ec965bf8109d390957fb112de0ff48cbd82c39b3f71095")]
        public void SigningKeyTest(string text, string sig)
        {
            var msg = System.Text.Encoding.UTF8.GetBytes(text);
            var base58 = new Base58(TestWif);
            var rez = _secp256H1.Sign(msg, base58);
            var sRez = Hex.ToString(rez);
            Assert.IsTrue(sig.Equals(sRez));
        }
    }
}