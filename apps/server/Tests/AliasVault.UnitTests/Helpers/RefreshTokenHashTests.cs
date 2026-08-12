//-----------------------------------------------------------------------
// <copyright file="RefreshTokenHashTests.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.UnitTests.Helpers;

using AliasVault.Api.Helpers;

/// <summary>
/// Tests for the refresh token hash that the database stores in place of the token itself.
/// </summary>
public class RefreshTokenHashTests
{
    /// <summary>
    /// The same token always hashes to the same value, so a stored token can be found again.
    /// </summary>
    [Test]
    public void HashIsStableTest()
    {
        const string token = "gQ7lLxQvZ0m2Yy7tE9d+Wc0nJk3sB1aRfP4uHt6XyZI=";

        var first = AuthHelper.HashRefreshToken(token);
        var second = AuthHelper.HashRefreshToken(string.Concat(token.AsSpan(0, 10), token.AsSpan(10)));

        Assert.That(second, Is.EqualTo(first));
    }

    /// <summary>
    /// Different tokens hash to different values.
    /// </summary>
    [Test]
    public void HashDiffersPerTokenTest()
    {
        var first = AuthHelper.HashRefreshToken("gQ7lLxQvZ0m2Yy7tE9d+Wc0nJk3sB1aRfP4uHt6XyZI=");
        var second = AuthHelper.HashRefreshToken("gQ7lLxQvZ0m2Yy7tE9d+Wc0nJk3sB1aRfP4uHt6XyZJ=");

        Assert.That(second, Is.Not.EqualTo(first));
    }

    /// <summary>
    /// The hash is not the token, so a database dump does not hand out sessions.
    /// </summary>
    [Test]
    public void HashDoesNotContainTokenTest()
    {
        const string token = "gQ7lLxQvZ0m2Yy7tE9d+Wc0nJk3sB1aRfP4uHt6XyZI=";

        Assert.That(AuthHelper.HashRefreshToken(token), Is.Not.EqualTo(token));
    }

    /// <summary>
    /// The hash fits the column that stores it, which holds 255 characters.
    /// </summary>
    [Test]
    public void HashFitsStorageColumnTest()
    {
        var hash = AuthHelper.HashRefreshToken(new string('a', 10000));

        Assert.That(hash, Has.Length.EqualTo(44));
    }

    /// <summary>
    /// The hash matches what the migration computes in SQL with
    /// encode(sha256(convert_to(value, 'UTF8')), 'base64'). If these ever diverge, upgrading would
    /// log every user out, so the expected values are pinned here.
    /// </summary>
    /// <param name="token">The token to hash.</param>
    /// <param name="expectedHash">The hash the migration produces for it.</param>
    [TestCase("gQ7lLxQvZ0m2Yy7tE9d+Wc0nJk3sB1aRfP4uHt6XyZI=", "473v16lehCuWSH0FQQ/jEnro7MwFtKDKHD78cN2O0W8=")]
    [TestCase("abc", "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=")]
    [TestCase("tok/with+special=chars==", "D1g/hbwGoULfTXROLIkxG6OcwWSqQ9voX4plKTY8CC4=")]
    public void HashMatchesMigrationSqlTest(string token, string expectedHash)
    {
        Assert.That(AuthHelper.HashRefreshToken(token), Is.EqualTo(expectedHash));
    }
}
