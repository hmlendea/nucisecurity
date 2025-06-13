using System.Collections.Generic;
using NuciSecurity.HMAC.UnitTests.Helpers;
using NUnit.Framework;

namespace NuciSecurity.HMAC.UnitTests
{
    public class DateTimeExtensionsTests
    {
        static string DummySharedSecretKey => "123DummySharedSecretKeyForTesting!";

        [Test]
        [TestCase("ThisWillBeUsed", "ThisWillNot", "nWVxAwKhNB/0bbQBLHSatlFgoahLhFCl7A3SGCjJd7lzCLyguP8qY3LeB4dADxH3PLIudyC0O83kAb/m6w0jrqaa")]
        [TestCase("ThisWillBeUsed", "ThisWillStillNotBeUsed", "nWVxAwKhNB/0bbQBLHSatlFgoahLhFCl7A3SGCjJd7lzCLyguP8qY3LeB4dADxH3PLIudyC0O83kAb/m6w0jrqaa")]
        [TestCase("UsedPropertyValue", "IgnoredPropertyValue", "bOE1GTNn/CHp/azhWTxQ2ibMxaHVI57zCX7rBfrIUM4jFFnXIYDuo6rhCQoxAoDtuZK6RLAoGEw9aYYVArFIoqaa")]
        [TestCase("UsedPropertyValue", "WhateverValueYay", "bOE1GTNn/CHp/azhWTxQ2ibMxaHVI57zCX7rBfrIUM4jFFnXIYDuo6rhCQoxAoDtuZK6RLAoGEw9aYYVArFIoqaa")]
        public void GivenAnObjectWithIgnoreAttributes_WhenGeneratingTheHmacToken_ThenTheExpectedValueIsReturned(
            string usedPropertyValue,
            string ignoredPropertyValue,
            string expectedHmacToken)
        {
            ObjectWithIgnoreAttributes obj = new()
            {
                UsedProperty = usedPropertyValue,
                IgnoredProperty = ignoredPropertyValue
            };

            Assert.That(HmacEncoder.GenerateToken(obj, DummySharedSecretKey), Is.EqualTo(expectedHmacToken));
        }

        [Test]
        [TestCase("prop1", "prop2")]
        [TestCase("123", "456")]
        public void GivenAnObjectWithOrderAttributes_WhenGeneratingTheHmacToken_ThenTheTokenWillDifferIfTheOrderIsChanged(
            string property1,
            string property2)
        {
            ObjectWithOrderAttributes obj1 = new()
            {
                Property1 = property1,
                Property2 = property2
            };
            ObjectWithDifferentOrderAttributes obj2 = new()
            {
                Property1 = property1,
                Property2 = property2
            };

            string token1 = HmacEncoder.GenerateToken(obj1, DummySharedSecretKey);
            string token2 = HmacEncoder.GenerateToken(obj2, DummySharedSecretKey);

            Assert.That(token1, Is.Not.EqualTo(token2));
        }

        [Test]
        public void GivenAnObjectWithCollectionProperties_WhenGeneratingTheHmacToken_ThenTheExpectedValueIsReturned()
        {
            ObjectWithCollectionProperties obj = new()
            {
                Collection =
                [
                    new() { UsedProperty = "Value1", IgnoredProperty = "Ignored1" },
                    new() { UsedProperty = "Value2", IgnoredProperty = "Ignored2" }
                ],
                Text = "Some text"
            };

            string expectedHmacToken = "WGEqsjT3pp0ysKtwvNKU/12duSLbLk/9+H3D6KdouVifpuTQHK5QMw8n+xvI1/LPLyHdNdkIqYg2NcgPZy/LQGaa";

            Assert.That(HmacEncoder.GenerateToken(obj, DummySharedSecretKey), Is.EqualTo(expectedHmacToken));
        }
    }
}
