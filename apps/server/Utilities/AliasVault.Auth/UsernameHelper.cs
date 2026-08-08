//-----------------------------------------------------------------------
// <copyright file="UsernameHelper.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.Auth;

/// <summary>
/// Helper for normalizing usernames consistently across the server.
/// </summary>
public static class UsernameHelper
{
    /// <summary>
    /// Normalizes a username by lowercasing and trimming it. 
    /// Used by all code paths that store a username.
    /// </summary>
    /// <param name="username">The username to normalize.</param>
    /// <returns>The normalized username.</returns>
    public static string NormalizeUsername(string username)
    {
        return username.ToLowerInvariant().Trim();
    }

    /// <summary>
    /// Shortens a username to at most the given number of characters.
    /// </summary>
    /// <remarks>
    /// Cuts on a character boundary rather than at the raw index. A char is a UTF-16 code unit, so an
    /// emoji or any other character outside the basic plane occupies two of them, and cutting between
    /// the two leaves a lone surrogate. That is not text: Npgsql writes strings with a UTF-8 encoder
    /// that rejects invalid input, so the lone surrogate turns the insert into an unhandled exception.
    /// Usernames reach this from unauthenticated request bodies, which is what makes it reachable.
    /// </remarks>
    /// <param name="username">The username to shorten.</param>
    /// <param name="maxLength">The maximum number of characters to keep.</param>
    /// <returns>The username, shortened when it exceeds the maximum length.</returns>
    public static string Truncate(string username, int maxLength)
    {
        if (username.Length <= maxLength)
        {
            return username;
        }

        // The character at maxLength - 1 is the last one kept. If it is the leading half of a surrogate
        // pair its trailing half falls outside the cut, so drop the pair rather than half of it.
        var length = maxLength;
        if (length > 0 && char.IsHighSurrogate(username[length - 1]))
        {
            length--;
        }

        return username[..length];
    }
}
