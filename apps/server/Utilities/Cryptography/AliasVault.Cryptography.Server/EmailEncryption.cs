//-----------------------------------------------------------------------
// <copyright file="EmailEncryption.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.Cryptography.Server;

using System.Security.Cryptography;
using AliasServerDb;

/// <summary>
/// Helper class for encrypting and decrypting email contents.
/// </summary>
public static class EmailEncryption
{
    /// <summary>
    /// Encrypt the email contents with the user's public key.
    /// </summary>
    /// <param name="email">The plain text email object to encrypt.</param>
    /// <param name="userEncryptionKey">The user public encryption key to use for the encryption.</param>
    /// <returns>Email object with all sensitive fields encrypted.</returns>
    public static Email EncryptEmail(Email email, UserEncryptionKey userEncryptionKey)
    {
        // Generate symmetric key for email encryption.
        var symmetricKey = Encryption.GenerateRandomSymmetricKey();

        // Encrypt all email contents with the symmetric key.
        if (email.MessageHtml is not null)
        {
            email.MessageHtml = Encryption.SymmetricEncrypt(email.MessageHtml, symmetricKey);
        }

        if (email.MessagePlain is not null)
        {
            email.MessagePlain = Encryption.SymmetricEncrypt(email.MessagePlain, symmetricKey);
        }

        if (email.MessagePreview is not null)
        {
            email.MessagePreview = Encryption.SymmetricEncrypt(email.MessagePreview, symmetricKey);
        }

        email.MessageSource = Encryption.SymmetricEncrypt(email.MessageSource, symmetricKey);
        email.Subject = Encryption.SymmetricEncrypt(email.Subject, symmetricKey);
        email.From = Encryption.SymmetricEncrypt(email.From, symmetricKey);
        email.FromLocal = Encryption.SymmetricEncrypt(email.FromLocal, symmetricKey);
        email.FromDomain = Encryption.SymmetricEncrypt(email.FromDomain, symmetricKey);

        // Encrypt all attachments with the symmetric key. The filename and MIME type are
        // encrypted too: the server has no use for them and they reveal what a user receives.
        foreach (var attachment in email.Attachments)
        {
            attachment.Bytes = Encryption.SymmetricEncrypt(attachment.Bytes, symmetricKey);
            attachment.Filename = Encryption.SymmetricEncrypt(attachment.Filename, symmetricKey);
            attachment.MimeType = Encryption.SymmetricEncrypt(attachment.MimeType, symmetricKey);
        }

        // Encrypt the symmetric key with the user's public key.
        email.EncryptedSymmetricKey = Encryption.EncryptSymmetricKeyWithRsa(symmetricKey, userEncryptionKey.PublicKey);
        email.UserEncryptionKeyId = userEncryptionKey.Id;

        return email;
    }

    /// <summary>
    /// Decrypt the email contents with the user's private key.
    /// </summary>
    /// <param name="email">The plain text email object to decrypt.</param>
    /// <param name="userPrivateKey">The user private encryption key to use for the decryption.</param>
    /// <returns>Email object with all sensitive fields decrypted.</returns>
    public static Email DecryptEmail(Email email, string userPrivateKey)
    {
        // Decrypt symmetric key using private key.
        var symmetricKey = Encryption.DecryptSymmetricKeyWithRsa(email.EncryptedSymmetricKey, userPrivateKey);

        // Encrypt all email contents with the symmetric key.
        if (email.MessageHtml is not null)
        {
            email.MessageHtml = Encryption.SymmetricDecrypt(email.MessageHtml, symmetricKey);
        }

        if (email.MessagePlain is not null)
        {
            email.MessagePlain = Encryption.SymmetricDecrypt(email.MessagePlain, symmetricKey);
        }

        if (email.MessagePreview is not null)
        {
            email.MessagePreview = Encryption.SymmetricDecrypt(email.MessagePreview, symmetricKey);
        }

        email.MessageSource = Encryption.SymmetricDecrypt(email.MessageSource, symmetricKey);
        email.Subject = Encryption.SymmetricDecrypt(email.Subject, symmetricKey);
        email.From = Encryption.SymmetricDecrypt(email.From, symmetricKey);
        email.FromLocal = Encryption.SymmetricDecrypt(email.FromLocal, symmetricKey);
        email.FromDomain = Encryption.SymmetricDecrypt(email.FromDomain, symmetricKey);

        foreach (var attachment in email.Attachments)
        {
            attachment.Filename = DecryptLegacyAware(attachment.Filename, symmetricKey);
            attachment.MimeType = DecryptLegacyAware(attachment.MimeType, symmetricKey);
        }

        return email;
    }

    /// <summary>
    /// Decrypts a value that may predate attachment metadata encryption.
    /// </summary>
    /// <remarks>
    /// Emails received before attachment metadata was encrypted still hold plaintext values, and
    /// they cannot be migrated: the per-email symmetric key is only recoverable with the user's
    /// private key, which the server does not have. Such values are returned as-is. AES-GCM
    /// verifies an authentication tag, so a plaintext value cannot be mistaken for ciphertext.
    /// </remarks>
    /// <param name="value">The stored value, either ciphertext or legacy plaintext.</param>
    /// <param name="symmetricKey">The symmetric key of the email.</param>
    /// <returns>The plaintext value.</returns>
    private static string DecryptLegacyAware(string value, byte[] symmetricKey)
    {
        try
        {
            return Encryption.SymmetricDecrypt(value, symmetricKey);
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or ArgumentException or OverflowException)
        {
            return value;
        }
    }
}
