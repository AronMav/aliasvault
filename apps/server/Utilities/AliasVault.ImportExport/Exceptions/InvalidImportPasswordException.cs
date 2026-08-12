//-----------------------------------------------------------------------
// <copyright file="InvalidImportPasswordException.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.ImportExport.Exceptions;

/// <summary>
/// Thrown when an encrypted import file cannot be decrypted with the supplied password.
/// Replaces matching on exception message text, which breaks whenever the wording changes.
/// </summary>
public class InvalidImportPasswordException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="InvalidImportPasswordException"/> class.
    /// </summary>
    /// <param name="message">The message describing the failure.</param>
    public InvalidImportPasswordException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="InvalidImportPasswordException"/> class.
    /// </summary>
    /// <param name="message">The message describing the failure.</param>
    /// <param name="innerException">The underlying exception.</param>
    public InvalidImportPasswordException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
