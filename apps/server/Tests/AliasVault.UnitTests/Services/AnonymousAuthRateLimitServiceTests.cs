//-----------------------------------------------------------------------
// <copyright file="AnonymousAuthRateLimitServiceTests.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.UnitTests.Services;

using AliasVault.Api.Services;

/// <summary>
/// Tests for <see cref="AnonymousAuthRateLimitService"/>, which caps what a single address can spend on
/// the authentication endpoints that need no authentication to reach.
/// </summary>
public class AnonymousAuthRateLimitServiceTests
{
    private const string Address = "203.0.113.10";

    /// <summary>
    /// Requests within the limit are allowed.
    /// </summary>
    [Test]
    public void RequestsWithinLimitAreAllowedTest()
    {
        using var service = new AnonymousAuthRateLimitService(3);

        Assert.Multiple(() =>
        {
            Assert.That(service.TryConsume(Address), Is.True);
            Assert.That(service.TryConsume(Address), Is.True);
            Assert.That(service.TryConsume(Address), Is.True);
        });
    }

    /// <summary>
    /// The request that goes past the limit is rejected, and so is everything after it in the same window.
    /// </summary>
    [Test]
    public void RequestsOverLimitAreRejectedTest()
    {
        using var service = new AnonymousAuthRateLimitService(2);

        service.TryConsume(Address);
        service.TryConsume(Address);

        Assert.Multiple(() =>
        {
            Assert.That(service.TryConsume(Address), Is.False);
            Assert.That(service.TryConsume(Address), Is.False);
        });
    }

    /// <summary>
    /// One address running out of allowance does not affect another, so a single abusive caller cannot
    /// lock everyone else out.
    /// </summary>
    [Test]
    public void LimitIsPerAddressTest()
    {
        using var service = new AnonymousAuthRateLimitService(1);

        service.TryConsume(Address);

        Assert.Multiple(() =>
        {
            Assert.That(service.TryConsume(Address), Is.False);
            Assert.That(service.TryConsume("198.51.100.7"), Is.True);
        });
    }

    /// <summary>
    /// A request whose address could not be determined is allowed through: rejecting it would turn an
    /// unresolvable address into a way to deny service.
    /// </summary>
    [Test]
    public void UnknownAddressIsAllowedTest()
    {
        using var service = new AnonymousAuthRateLimitService(1);

        Assert.Multiple(() =>
        {
            Assert.That(service.TryConsume(null), Is.True);
            Assert.That(service.TryConsume(null), Is.True);
            Assert.That(service.TryConsume(string.Empty), Is.True);
        });
    }

    /// <summary>
    /// A limit of zero disables the limiter.
    /// </summary>
    [Test]
    public void ZeroLimitDisablesLimitingTest()
    {
        using var service = new AnonymousAuthRateLimitService(0);

        for (var i = 0; i < 100; i++)
        {
            Assert.That(service.TryConsume(Address), Is.True);
        }
    }
}
