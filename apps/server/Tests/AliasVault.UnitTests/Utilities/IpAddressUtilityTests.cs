//-----------------------------------------------------------------------
// <copyright file="IpAddressUtilityTests.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.UnitTests.Utilities;

using System.Net;
using AliasVault.Auth.IpAddress;
using Microsoft.AspNetCore.Http;

/// <summary>
/// Tests that the client IP used for access decisions cannot be chosen by the client.
/// </summary>
public class IpAddressUtilityTests
{
    /// <summary>
    /// Tests that a client-supplied X-Forwarded-For header cannot override the real peer.
    /// </summary>
    [Test]
    public void ClientSuppliedForwardedForIsIgnored()
    {
        var context = CreateContext("203.0.113.9");
        context.Request.Headers["X-Forwarded-For"] = "1.2.3.4";

        var result = IpAddressUtility.GetRawIpAddressFromContext(context);

        Assert.That(result?.ToString(), Is.EqualTo("203.0.113.9"));
    }

    /// <summary>
    /// Tests that a client-supplied X-Real-IP is ignored when the request arrives directly
    /// from the internet rather than through a reverse proxy on our own network.
    /// </summary>
    [Test]
    public void ClientSuppliedRealIpFromPublicPeerIsIgnored()
    {
        var context = CreateContext("203.0.113.9");
        context.Request.Headers["X-Real-IP"] = "1.2.3.4";

        var result = IpAddressUtility.GetRawIpAddressFromContext(context);

        Assert.That(result?.ToString(), Is.EqualTo("203.0.113.9"));
    }

    /// <summary>
    /// Tests that a well-formed X-Real-IP set by the bundled reverse proxy is honoured. The proxy runs
    /// on the container network, so it reaches the API from a private address.
    /// </summary>
    [Test]
    public void RealIpFromReverseProxyIsHonoured()
    {
        var context = CreateContext("172.18.0.5");
        context.Request.Headers["X-Real-IP"] = "198.51.100.7";

        var result = IpAddressUtility.GetRawIpAddressFromContext(context);

        Assert.That(result?.ToString(), Is.EqualTo("198.51.100.7"));
    }

    /// <summary>
    /// Tests that an X-Real-IP value that does not parse as an address is NOT honoured: falling
    /// through with it would surface a null client address downstream, silently disabling the IP
    /// block list and the per-address anonymous-auth limit. The connection peer is used instead,
    /// keeping the request metered and checked.
    /// </summary>
    [Test]
    public void UnparseableRealIpFallsBackToPeer()
    {
        var context = CreateContext("172.18.0.5");
        context.Request.Headers["X-Real-IP"] = "garbage";

        var result = IpAddressUtility.GetRawIpAddressFromContext(context);

        Assert.That(result?.ToString(), Is.EqualTo("172.18.0.5"));
    }

    /// <summary>
    /// Tests that a spoofed X-Forwarded-For cannot win over the value the proxy vouched for.
    /// </summary>
    [Test]
    public void ForwardedForCannotOverrideProxySuppliedRealIp()
    {
        var context = CreateContext("172.18.0.5");
        context.Request.Headers["X-Real-IP"] = "198.51.100.7";
        context.Request.Headers["X-Forwarded-For"] = "1.2.3.4";

        var result = IpAddressUtility.GetRawIpAddressFromContext(context);

        Assert.That(result?.ToString(), Is.EqualTo("198.51.100.7"));
    }

    /// <summary>
    /// Tests that the peer address is used when no proxy header is present.
    /// </summary>
    [Test]
    public void PeerAddressIsUsedWithoutProxyHeaders()
    {
        var context = CreateContext("203.0.113.9");

        var result = IpAddressUtility.GetRawIpAddressFromContext(context);

        Assert.That(result?.ToString(), Is.EqualTo("203.0.113.9"));
    }

    /// <summary>
    /// Tests that anonymized logging follows the same rules, so a spoofed header cannot
    /// put an arbitrary address into the admin auth log.
    /// </summary>
    [Test]
    public void AnonymizedAddressIgnoresClientSuppliedHeader()
    {
        var context = CreateContext("203.0.113.9");
        context.Request.Headers["X-Forwarded-For"] = "1.2.3.4";

        var result = IpAddressUtility.GetAnonymizedIpFromContext(context);

        Assert.That(result, Is.EqualTo("203.0.113.xxx"));
    }

    /// <summary>
    /// Creates an HttpContext whose connection originates from the given address.
    /// </summary>
    /// <param name="remoteIp">The address of the immediate peer.</param>
    /// <returns>An HttpContext for use in the tests.</returns>
    private static DefaultHttpContext CreateContext(string remoteIp)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(remoteIp);
        return context;
    }
}
