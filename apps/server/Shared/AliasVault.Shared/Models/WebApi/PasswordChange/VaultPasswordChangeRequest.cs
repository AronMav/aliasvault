//-----------------------------------------------------------------------
// <copyright file="VaultPasswordChangeRequest.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.Shared.Models.WebApi.PasswordChange;

using AliasVault.Shared.Models.WebApi.Vault;

/// <summary>
/// Represents a request to change the users password including a new vault that is encrypted with the new password.
/// </summary>
public class VaultPasswordChangeRequest : Vault
{
    /// <summary>
    /// Gets or sets the client's public ephemeral for the current password verification.
    /// </summary>
    public required string CurrentClientPublicEphemeral { get; set; }

    /// <summary>
    /// Gets or sets the client's session proof for the current password verification.
    /// </summary>
    public required string CurrentClientSessionProof { get; set; }

    /// <summary>
    /// Gets or sets the new password salt.
    /// </summary>
    public required string NewPasswordSalt { get; set; }

    /// <summary>
    /// Gets or sets the new password verifier.
    /// </summary>
    public required string NewPasswordVerifier { get; set; }

    /// <summary>
    /// Gets or sets the encryption type the client derived the new verifier with.
    /// Null when the client predates this field, in which case the server records its own defaults.
    /// </summary>
    public string? NewPasswordEncryptionType { get; set; }

    /// <summary>
    /// Gets or sets the encryption settings the client derived the new verifier with.
    /// Null when the client predates this field, in which case the server records its own defaults.
    /// </summary>
    /// <remarks>
    /// The vault can only be opened again with the parameters its key was derived under, so these
    /// have to be what the client actually used rather than what the server would have chosen.
    /// </remarks>
    public string? NewPasswordEncryptionSettings { get; set; }
}
