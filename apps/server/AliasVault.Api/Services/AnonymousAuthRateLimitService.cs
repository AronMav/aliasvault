//-----------------------------------------------------------------------
// <copyright file="AnonymousAuthRateLimitService.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.Api.Services;

using System;
using System.Threading;
using Microsoft.Extensions.Caching.Memory;

/// <summary>
/// In-memory per-IP rate limiter for the authentication endpoints an unauthenticated caller can reach.
/// Those endpoints each spend something real per request -- a modular exponentiation to produce an SRP
/// ephemeral, or a database row that lives until the retention task removes it -- so without a limit a
/// single caller decides how much CPU and storage the instance spends.
/// </summary>
/// <remarks>
/// <para>
/// The window is a fixed one-minute bucket rather than a rolling window: a caller can burst up to twice
/// the limit across a bucket boundary, which is irrelevant at the volumes this is meant to stop and
/// costs a fraction of the bookkeeping.
/// </para>
/// <para>
/// State is held in process and is not shared across instances, matching how the favicon limiter works.
/// The number of tracked addresses is capped, because the key is an address from an unauthenticated
/// request: the cache evicts the least recently used entries once the cap is reached, so the limiter
/// cannot itself become the memory growth it exists to prevent.
/// </para>
/// </remarks>
public sealed class AnonymousAuthRateLimitService : IDisposable
{
    /// <summary>
    /// Default maximum requests per IP address per minute. A client sends one request per login it
    /// starts, so this leaves room for many users behind a single address while bounding what one
    /// caller can spend.
    /// </summary>
    public const int DefaultMaxPerMinute = 60;

    /// <summary>
    /// Maximum number of addresses tracked at once.
    /// </summary>
    private const int MaxTrackedAddresses = 20000;

    private static readonly TimeSpan WindowDuration = TimeSpan.FromMinutes(1);

    private readonly MemoryCache _windows;
    private readonly int _maxPerMinute;

    /// <summary>
    /// Initializes a new instance of the <see cref="AnonymousAuthRateLimitService"/> class, reading the
    /// limit from the MAX_AUTH_REQUESTS_PER_IP_PER_MINUTE environment variable when it is set.
    /// </summary>
    public AnonymousAuthRateLimitService()
        : this(ReadConfiguredLimit())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AnonymousAuthRateLimitService"/> class with an
    /// explicit limit.
    /// </summary>
    /// <param name="maxPerMinute">Maximum requests allowed per IP address per minute. Set to 0 or less to disable.</param>
    public AnonymousAuthRateLimitService(int maxPerMinute)
    {
        _maxPerMinute = maxPerMinute;
        _windows = new MemoryCache(new MemoryCacheOptions { SizeLimit = MaxTrackedAddresses });
    }

    /// <summary>
    /// Records a request from the given address and reports whether it still fits in the allowance.
    /// </summary>
    /// <param name="ipAddress">The address the request came from, or null when it cannot be determined.</param>
    /// <returns>True if the request is within the limit; false if it exceeds it and should be rejected.</returns>
    public bool TryConsume(string? ipAddress)
    {
        if (_maxPerMinute <= 0 || string.IsNullOrEmpty(ipAddress))
        {
            return true;
        }

        var window = _windows.GetOrCreate(ipAddress, entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = WindowDuration;
            entry.Size = 1;
            return new RequestWindow();
        })!;

        return window.Increment() <= _maxPerMinute;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _windows.Dispose();
    }

    /// <summary>
    /// Reads the configured limit from the environment, falling back to the default.
    /// </summary>
    /// <returns>The maximum number of requests per IP address per minute.</returns>
    private static int ReadConfiguredLimit()
    {
        var configured = Environment.GetEnvironmentVariable("MAX_AUTH_REQUESTS_PER_IP_PER_MINUTE");
        return int.TryParse(configured, out var parsed) ? parsed : DefaultMaxPerMinute;
    }

    /// <summary>
    /// The request count for one address within one window.
    /// </summary>
    private sealed class RequestWindow
    {
        private int _count;

        /// <summary>
        /// Counts one request against this window.
        /// </summary>
        /// <returns>The number of requests counted in this window so far, including this one.</returns>
        public int Increment()
        {
            return Interlocked.Increment(ref _count);
        }
    }
}
