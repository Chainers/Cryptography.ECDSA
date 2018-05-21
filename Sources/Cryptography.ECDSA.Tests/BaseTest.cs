using Xunit.Abstractions;

namespace Cryptography.ECDSA.Tests
{
    public class BaseTest
    {
        protected readonly ITestOutputHelper Output;

        public BaseTest(ITestOutputHelper output)
        {
            Output = output;
        }

        protected void WriteLine(string s)
        {
            Output.WriteLine(s);
        }

    }
}