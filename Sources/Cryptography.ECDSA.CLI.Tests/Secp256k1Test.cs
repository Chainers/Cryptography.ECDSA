using NUnit.Framework;

namespace Cryptography.ECDSA.Tests
{
    [TestFixture]
    public class Secp256k1Test
    {
        protected const string TestWif = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP78zkvFD3";

        [Test]
        [TestCase("Hello world", "1fa6bae619f0a293190572523c7fa0f9274e9a1fbb19053b3f0dd7346ccdf0f08e78c66c23021023159d54bac0a0b913ede5bd4d4a28446039559dcf802f4aefff")]
        public void SigningKeyTest(string text, string sig)
        {
            var msg = System.Text.Encoding.UTF8.GetBytes(text);
            var hex = Base58.GetBytes(TestWif);
            var digest = Proxy.GetMessageHash(msg);
            int recId;
            var signature = Proxy.SignCompact(digest, hex, out recId);
            Assert.IsTrue(signature.Length == 64);

            var sRez = Hex.ToString(Hex.Join(new[] { (byte)(recId + 4 + 27) }, signature));
            Assert.IsTrue(sig.Equals(sRez), $"Expected:{sig} but was {sRez}");
        }
    }
}