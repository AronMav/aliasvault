//-----------------------------------------------------------------------
// <copyright file="UsernameTruncationTests.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.UnitTests.Helpers;

using System.Text;
using AliasVault.Auth;

/// <summary>
/// Tests for <see cref="UsernameHelper.Truncate"/>, which bounds a username that arrived in an
/// unauthenticated request body before anything stores it.
/// </summary>
public class UsernameTruncationTests
{
    /// <summary>
    /// The encoder Npgsql writes strings with. It rejects anything that is not valid UTF-16, which is
    /// what makes a badly cut username an unhandled exception rather than a stored value.
    /// </summary>
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// A username within the limit is returned unchanged.
    /// </summary>
    [Test]
    public void ShorterThanTheLimitIsUnchangedTest()
    {
        Assert.That(UsernameHelper.Truncate("someone@test.com", 255), Is.EqualTo("someone@test.com"));
    }

    /// <summary>
    /// A username of plain characters is cut to exactly the limit.
    /// </summary>
    [Test]
    public void PlainTextIsCutToTheLimitTest()
    {
        var truncated = UsernameHelper.Truncate(new string('a', 300), 255);

        Assert.That(truncated, Has.Length.EqualTo(255));
    }

    /// <summary>
    /// A character that spans two UTF-16 units is dropped whole rather than cut in half.
    /// </summary>
    /// <remarks>
    /// Cutting between the two halves leaves a lone surrogate, which is not text. The value goes
    /// straight into the auth log from the login endpoint, so a caller who puts an emoji on the
    /// boundary would otherwise turn an anonymous request into a failed insert.
    /// </remarks>
    [Test]
    public void CharacterOnTheBoundaryIsNotSplitTest()
    {
        // 254 plain characters plus a two-unit emoji: the cut at 255 lands between its halves.
        var username = new string('a', 254) + "\U0001F600";
        var truncated = UsernameHelper.Truncate(username, 255);

        Assert.Multiple(() =>
        {
            Assert.That(truncated, Has.Length.EqualTo(254), "The emoji should have been dropped whole.");
            Assert.That(truncated.Any(char.IsSurrogate), Is.False, "A half of a surrogate pair was left behind.");
            Assert.DoesNotThrow(() => StrictUtf8.GetBytes(truncated), "The result cannot be written as UTF-8.");
        });
    }

    /// <summary>
    /// A character that ends exactly on the limit is kept, because both of its halves fit.
    /// </summary>
    [Test]
    public void CharacterEndingOnTheLimitIsKeptTest()
    {
        // 253 plain characters plus a two-unit emoji: the pair ends exactly at 255.
        var username = new string('a', 253) + "\U0001F600" + new string('b', 50);
        var truncated = UsernameHelper.Truncate(username, 255);

        Assert.Multiple(() =>
        {
            Assert.That(truncated, Has.Length.EqualTo(255));
            Assert.That(truncated, Does.EndWith("\U0001F600"));
            Assert.DoesNotThrow(() => StrictUtf8.GetBytes(truncated));
        });
    }

    /// <summary>
    /// Whatever the cut lands on, the result is always writable as UTF-8.
    /// </summary>
    /// <param name="prefixLength">Number of plain characters placed before the emoji.</param>
    [TestCase(250)]
    [TestCase(251)]
    [TestCase(252)]
    [TestCase(253)]
    [TestCase(254)]
    [TestCase(255)]
    [TestCase(256)]
    public void ResultIsAlwaysEncodableTest(int prefixLength)
    {
        var username = new string('a', prefixLength) + "\U0001F600" + new string('b', 300);
        var truncated = UsernameHelper.Truncate(username, 255);

        Assert.Multiple(() =>
        {
            Assert.That(truncated, Has.Length.LessThanOrEqualTo(255));
            Assert.DoesNotThrow(() => StrictUtf8.GetBytes(truncated));
        });
    }
}
