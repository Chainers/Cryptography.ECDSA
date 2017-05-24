using Cryptography.ECDSA.Curves;
using NUnit.Framework;

namespace Cryptography.ECDSA.Tests
{
    [TestFixture]
    public class Secp256p1Test
    {
        protected const string TestWif = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3";
        readonly Secp256K1 _secp256H1 = new Secp256K1();

        [Test]
        [TestCase("Hello world", "20097720fdc7ae554cd14486db5c0d5bf97d41be56702437b81155a39ec6120d73530bc8a476916b9df02e96712ca75497ca09cd0bfd8f0b1f571d80b8b6d49b05")]
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