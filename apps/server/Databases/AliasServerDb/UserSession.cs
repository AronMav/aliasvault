//-----------------------------------------------------------------------
// <copyright file="UserSession.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasServerDb;

using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;

/// <summary>
/// Durable session identity. Revocation survives refresh-token rotation and concurrent requests.
/// </summary>
[Index(nameof(UserId))]
public class UserSession
{
    /// <summary>Gets or sets the session identity.</summary>
    public Guid Id { get; set; }

    /// <summary>Gets or sets the owning user.</summary>
    [MaxLength(255)]
    public string UserId { get; set; } = null!;

    /// <summary>Gets or sets the user navigation.</summary>
    public virtual AliasVaultUser User { get; set; } = null!;

    /// <summary>Gets or sets the creation time.</summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>Gets or sets the irreversible revocation time.</summary>
    public DateTime? RevokedAt { get; set; }
}
