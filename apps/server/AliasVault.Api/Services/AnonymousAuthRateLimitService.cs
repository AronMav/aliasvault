//-----------------------------------------------------------------------
// <copyright file="AnonymousAuthRateLimitService.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.Api.Services;

using System;
using System.Threading;

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
/// Counts live in a fixed array of slots indexed by a hash of the address, not in a dictionary or cache
/// keyed by it. The address comes from an unauthenticated request, so anything that grows per address
/// has to decide what to do when it is full, and the obvious answers are both wrong: refusing new
/// entries hands an attacker a way to lock everyone else out, and dropping them silently -- which is
/// what a size-limited MemoryCache does -- stops counting the flood entirely, exactly when the limit
/// matters. A fixed array can never be full, so neither case can arise.
/// </para>
/// <para>
/// The cost is that two addresses hashing to the same slot share one allowance. That errs towards
/// rejecting rather than admitting, and with <see cref="SlotCount"/> slots against the number of
/// addresses a real instance sees in a minute it is rare; under a flood large enough to make collisions
/// common, counting several attackers together is the behaviour you want. String hashing is randomized
/// per process, so the collisions cannot be chosen from outside.
/// </para>
/// <para>
/// State is held in process and is not shared across instances, matching how the favicon limiter works.
/// </para>
/// </remarks>
public sealed class AnonymousAuthRateLimitService
{
    /// <summary>
    /// Default maximum requests per IP address per minute.
    /// </summary>
    /// <remarks>
    /// One completed login spends two of these -- starting the exchange and proving against it -- and
    /// three when a second factor is involved, so this allows roughly twenty to thirty logins a minute
    /// from a single address. That is ample for the number of people a self-hosted instance puts behind
    /// one address; a deployment where far more users share an address, such as a large office behind
    /// NAT, should raise MAX_AUTH_REQUESTS_PER_IP_PER_MINUTE to match.
    /// </remarks>
    public const int DefaultMaxPerMinute = 60;

    /// <summary>
    /// Number of counter slots. A power of two so the slot index is a mask rather than a division, and
    /// large enough that collisions stay rare at the number of addresses an instance sees in a minute.
    /// At 8 bytes per slot the whole table is half a megabyte, allocated once.
    /// </summary>
    private const int SlotCount = 1 << 16;

    /// <summary>
    /// Bucket key used for every caller whose address could not be determined, so those requests are
    /// metered against one shared allowance instead of being admitted unmetered. Deliberately not a
    /// string that could ever equal a parsed address.
    /// </summary>
    private const string UnknownAddressKey = "\x00undetermined";

    /// <summary>
    /// Length of one counting window, in milliseconds.
    /// </summary>
    private const long WindowMilliseconds = 60_000;

    /// <summary>
    /// One slot per hash bucket, each packing the window it belongs to in the high 32 bits and the
    /// number of requests counted in that window in the low 32 bits, so a slot updates atomically.
    /// </summary>
    private readonly long[] _slots = new long[SlotCount];

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
    }

    /// <summary>
    /// Records a request from the given address and reports whether it still fits in the allowance.
    /// </summary>
    /// <param name="ipAddress">The address the request came from, or null when it cannot be determined.
    /// Callers with an undetermined address all share one metered bucket; they are never let through
    /// unmetered.</param>
    /// <returns>True if the request is within the limit; false if it exceeds it and should be rejected.</returns>
    public bool TryConsume(string? ipAddress)
    {
        if (_maxPerMinute <= 0)
        {
            return true;
        }

        // A caller whose address cannot be determined is counted in one shared bucket with every
        // other such caller instead of being admitted unmetered. Unlimited access would let any
        // caller who hides their address spend without bound, while refusing the request outright
        // would turn an unresolvable address into a denial of service. A bounded shared bucket
        // fails closed without either hole.
        var key = string.IsNullOrEmpty(ipAddress) ? UnknownAddressKey : ipAddress;

        var slot = key.GetHashCode(StringComparison.Ordinal) & (SlotCount - 1);

        // Wrapping is fine: windows are only ever compared for equality, and a wrap at worst restarts
        // one window early, which costs a single caller nothing and happens once every few millennia.
        var window = unchecked((int)(Environment.TickCount64 / WindowMilliseconds));

        while (true)
        {
            var current = Volatile.Read(ref _slots[slot]);
            var currentWindow = (int)(current >> 32);
            var currentCount = (int)(uint)current;

            // A slot left over from an earlier window carries no count into this one.
            var count = currentWindow == window ? currentCount + 1 : 1;

            // Stop climbing once the answer can no longer change, so a flood that lasts a whole window
            // cannot run the counter over.
            if (count > _maxPerMinute)
            {
                count = _maxPerMinute + 1;
            }

            var updated = ((long)window << 32) | (uint)count;
            if (Interlocked.CompareExchange(ref _slots[slot], updated, current) == current)
            {
                return count <= _maxPerMinute;
            }
        }
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
}
