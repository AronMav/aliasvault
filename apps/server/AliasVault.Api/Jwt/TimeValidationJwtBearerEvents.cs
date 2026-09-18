// -----------------------------------------------------------------------
// <copyright file="TimeValidationJwtBearerEvents.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
// -----------------------------------------------------------------------

namespace AliasVault.Api.Jwt;

using System.Security.Claims;
using AliasServerDb;
using AliasVault.Shared.Providers.Time;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;

/// <summary>
/// JwtBearerEvents implementation that validates the token expiration time based on
/// the current time provided by an ITimeProvider. This is used to be able to
/// test the token expiration logic in unit tests.
/// </summary>
public class TimeValidationJwtBearerEvents(ITimeProvider timeProvider, IAliasServerDbContextFactory dbContextFactory) : JwtBearerEvents
{
    /// <summary>
    /// Validates the token expiration time based on the current time provided by the ITimeProvider.
    /// </summary>
    /// <param name="context">TokenValidatedContext.</param>
    /// <returns>Async task.</returns>
    public override async Task TokenValidated(TokenValidatedContext context)
    {
        if (context.SecurityToken is JsonWebToken jwtToken)
        {
            if (jwtToken.ValidTo < timeProvider.UtcNow)
            {
                context.Fail("Token has expired.");
                return;
            }
        }

        var userId = context.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId is null || !Guid.TryParse(context.Principal?.FindFirstValue("sid"), out var sessionId))
        {
            // Older access tokens must refresh once to obtain a session-bound token.
            context.Fail("Session is no longer valid.");
            return;
        }

        await using var db = await dbContextFactory.CreateDbContextAsync(context.HttpContext.RequestAborted);
        var now = timeProvider.UtcNow;
        if (!await db.AliasVaultUserRefreshTokens.AnyAsync(
            t => t.UserId == userId && t.SessionId == sessionId && t.ExpireDate > now && !t.User.Blocked && t.Session.RevokedAt == null,
            context.HttpContext.RequestAborted))
        {
            context.Fail("Session is no longer valid.");
        }
    }
}
