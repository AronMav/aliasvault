//-----------------------------------------------------------------------
// <copyright file="TrustedProxyUtility.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.Auth.IpAddress;

using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

/// <summary>Recognizes loopback and explicitly configured application proxies.</summary>
public static class TrustedProxyUtility
{
    private static readonly ConcurrentDictionary<string, (IPAddress[] Addresses, DateTime Expires)> HostAddresses = new();

    /// <summary>Checks the socket peer, never a request header, against TRUSTED_APP_PROXIES.</summary>
    /// <param name="peer">The immediate socket peer.</param>
    /// <returns>Whether this peer may supply forwarding headers.</returns>
    public static bool IsTrusted(IPAddress? peer)
    {
        if (peer is null)
        {
            return false;
        }

        peer = IpRangeUtility.NormalizeAddress(peer);
        if (IPAddress.IsLoopback(peer))
        {
            return true;
        }

        foreach (var entry in (Environment.GetEnvironmentVariable("TRUSTED_APP_PROXIES") ?? string.Empty).Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (IPAddress.TryParse(entry, out var address))
            {
                if (IpRangeUtility.NormalizeAddress(address).Equals(peer))
                {
                    return true;
                }
            }
            else if (System.Net.IPNetwork.TryParse(entry, out var network))
            {
                if (network.Contains(peer))
                {
                    return true;
                }
            }
            else if (!entry.Contains('/') && Uri.CheckHostName(entry) == UriHostNameType.Dns)
            {
                // Resolve only operator-configured names (e.g. the Docker service), never user input.
                // Cache briefly so a recreated proxy container does not require an application restart.
                if (!HostAddresses.TryGetValue(entry, out var cached) || cached.Expires <= DateTime.UtcNow)
                {
                    try
                    {
                        cached = (Dns.GetHostAddresses(entry), DateTime.UtcNow.AddMinutes(1));
                    }
                    catch (SocketException)
                    {
                        cached = ([], DateTime.UtcNow.AddSeconds(10));
                    }

                    HostAddresses[entry] = cached;
                }

                if (cached.Addresses.Any(candidate => IpRangeUtility.NormalizeAddress(candidate).Equals(peer)))
                {
                    return true;
                }
            }
        }

        return false;
    }
}
