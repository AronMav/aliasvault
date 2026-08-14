//-----------------------------------------------------------------------
// <copyright file="IpAddressUtility.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.Auth.IpAddress;

using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Http;

/// <summary>
/// Ip address utility class to extract the client IP address from HttpContext.
/// </summary>
public static class IpAddressUtility
{
    /// <summary>
    /// Fully anonymized IP address constant used when IP logging is disabled.
    /// </summary>
    public const string AnonymizedIp = "xxx.xxx.xxx.xxx";

    /// <summary>
    /// The header which contains the resolved client IP address. This is set by nginx (which ships with AliasVault).
    /// </summary>
    private const string RealIpHeader = "X-Real-IP";

    /// <summary>
    /// Extracts the anonymized IP address (IPv4 last octet masked) from the HttpContext for persistence/logging.
    /// </summary>
    /// <param name="httpContext">HttpContext to extract the IP address from.</param>
    /// <param name="ipLoggingEnabled">Whether IP logging is enabled. If false, returns fully anonymized IP.</param>
    /// <returns>Anonymized IP address.</returns>
    public static string GetAnonymizedIpFromContext(HttpContext? httpContext, bool ipLoggingEnabled = true)
    {
        if (!ipLoggingEnabled)
        {
            return AnonymizedIp;
        }

        if (httpContext == null)
        {
            return string.Empty;
        }

        var ipAddress = ExtractIpAddress(httpContext)?.ToString() ?? "0.0.0.0";

        // Anonymize the last octet of the IP address (IPv4 only).
        if (ipAddress.Contains('.'))
        {
            try
            {
                var parts = ipAddress.Split('.');
                ipAddress = parts[0] + "." + parts[1] + "." + parts[2] + ".xxx";
            }
            catch
            {
                // If an exception occurs, continue execution with original IP address.
            }
        }

        return ipAddress;
    }

    /// <summary>
    /// Extracts the raw, non-anonymized IP address from the HttpContext for transient, request-time use only
    /// (e.g. matching against the IP blocklist). The returned value is intentionally NOT anonymized and must
    /// never be persisted. Use GetAnonymizedIpFromContext for persistence/logging instead.
    /// </summary>
    /// <param name="httpContext">HttpContext to extract the IP address from.</param>
    /// <returns>The parsed IP address, or null when it cannot be determined.</returns>
    public static IPAddress? GetRawIpAddressFromContext(HttpContext? httpContext)
    {
        if (httpContext == null)
        {
            return null;
        }

        return ExtractIpAddress(httpContext);
    }

    /// <summary>
    /// Resolves the client IP address for the request.
    /// </summary>
    /// <param name="httpContext">HttpContext to extract the IP address from.</param>
    /// <returns>The parsed IP address, or null when it cannot be determined.</returns>
    private static IPAddress? ExtractIpAddress(HttpContext httpContext)
    {
        if (!IPAddress.TryParse(ExtractRawIpString(httpContext), out var parsed))
        {
            return null;
        }

        return IpRangeUtility.NormalizeAddress(parsed);
    }

    /// <summary>
    /// Extracts the raw IP address string from the X-Real-IP header set by nginx, falling back to the connection's
    /// </summary>
    /// <remarks>
    /// Only a reverse proxy reaching us over a private network may name the client. The bundled
    /// nginx sets X-Real-IP from the connection it accepted, so that value is trustworthy; the
    /// leftmost X-Forwarded-For entry is not, because nginx appends to whatever the client sent.
    /// Honouring it would let anyone pick their own address and walk past the IP block list and
    /// the per-IP registration limit.
    /// </remarks>
    /// <param name="httpContext">HttpContext to extract the IP address from.</param>
    /// <returns>The raw IP address string, or null when it cannot be determined.</returns>
    private static string? ExtractRawIpString(HttpContext httpContext)
    {
        // Only a reverse proxy reaching us over a private network may name the client
        // (see the remarks on ExtractRawIpString above). A request straight from the
        // internet that carries X-Real-IP must not get that header honoured: anyone
        // could set it and pick the address the block list and registration limits see.
        var peer = httpContext.Connection.RemoteIpAddress;
        if (IsPrivatePeer(peer) && httpContext.Request.Headers.TryGetValue(RealIpHeader, out var realIp))
        {
            var lastEntry = realIp.ToString().Split(',')[^1].Trim();
            if (lastEntry.Length > 0)
            {
                return lastEntry;
            }
        }

        return httpContext.Connection.RemoteIpAddress?.ToString();
    }

    /// <summary>
    /// Determines whether the immediate peer sits on a private network, and may therefore be a
    /// reverse proxy of ours rather than an arbitrary client from the internet.
    /// </summary>
    /// <param name="address">The address of the immediate peer.</param>
    /// <returns>True when the peer address is loopback or in a private range.</returns>
    private static bool IsPrivatePeer(IPAddress? address)
    {
        if (address is null)
        {
            return false;
        }

        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6UniqueLocal)
        {
            return true;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        var octets = address.GetAddressBytes();
        return octets[0] switch
        {
            10 => true,
            172 => octets[1] >= 16 && octets[1] <= 31,
            192 => octets[1] == 168,
            _ => false,
        };
    }
}
