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
        var service = new AnonymousAuthRateLimitService(3);

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
        var service = new AnonymousAuthRateLimitService(2);

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
        var service = new AnonymousAuthRateLimitService(1);

        service.TryConsume(Address);

        Assert.Multiple(() =>
        {
            Assert.That(service.TryConsume(Address), Is.False);
            Assert.That(service.TryConsume("198.51.100.7"), Is.True);
        });
    }

    /// <summary>
    /// Requests whose address cannot be determined are metered against one shared bucket: within the
    /// allowance they pass, and once the shared allowance is spent further such requests are rejected.
    /// Admitting them unmetered would let a caller who hides their address spend without bound.
    /// </summary>
    [Test]
    public void UnknownAddressIsMeteredTest()
    {
        var service = new AnonymousAuthRateLimitService(2);

        Assert.Multiple(() =>
        {
            Assert.That(service.TryConsume(null), Is.True);
            Assert.That(service.TryConsume(string.Empty), Is.True);
            Assert.That(service.TryConsume(null), Is.False);
            Assert.That(service.TryConsume(string.Empty), Is.False);
        });
    }

    /// <summary>
    /// The shared undetermined-address bucket is independent of the buckets of real addresses, so a
    /// flood from an unresolvable address cannot exhaust someone else's allowance.
    /// </summary>
    [Test]
    public void UnknownAddressBucketIsIndependentTest()
    {
        var service = new AnonymousAuthRateLimitService(1);

        service.TryConsume(null);

        Assert.Multiple(() =>
        {
            Assert.That(service.TryConsume(null), Is.False);
            Assert.That(service.TryConsume(Address), Is.True);
        });
    }

    /// <summary>
    /// A limit of zero disables the limiter.
    /// </summary>
    [Test]
    public void ZeroLimitDisablesLimitingTest()
    {
        var service = new AnonymousAuthRateLimitService(0);

        for (var i = 0; i < 100; i++)
        {
            Assert.That(service.TryConsume(Address), Is.True);
        }
    }

    /// <summary>
    /// The limit still applies after a large number of distinct addresses have been seen.
    /// </summary>
    /// <remarks>
    /// This is the case the limiter exists for: a flood arrives from many source addresses at once. An
    /// implementation that tracks addresses in a container with a capacity stops counting once that
    /// capacity is reached and lets every subsequent caller through unmetered, so the limit disappears
    /// exactly when it is needed. Whatever holds the counts has to keep counting here.
    /// </remarks>
    [Test]
    public void LimitStillAppliesAfterManyDistinctAddressesTest()
    {
        const int limit = 5;
        var service = new AnonymousAuthRateLimitService(limit);

        for (var i = 0; i < 100_000; i++)
        {
            service.TryConsume($"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}");
        }

        var allowed = 0;
        for (var i = 0; i < limit * 20; i++)
        {
            if (service.TryConsume(Address))
            {
                allowed++;
            }
        }

        Assert.That(allowed, Is.LessThanOrEqualTo(limit), "The limiter stopped counting once it had seen many addresses.");
    }
}
