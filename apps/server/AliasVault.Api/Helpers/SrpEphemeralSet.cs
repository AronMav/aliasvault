//-----------------------------------------------------------------------
// <copyright file="SrpEphemeralSet.cs" company="aliasvault">
// Copyright (c) aliasvault. All rights reserved.
// Licensed under the AGPLv3 license. See LICENSE.md file in the project root for full license information.
// </copyright>
//-----------------------------------------------------------------------

namespace AliasVault.Api.Helpers;

/// <summary>
/// The server SRP ephemeral secrets currently live for one account.
/// </summary>
/// <remarks>
/// An account can have more than one login in flight at a time — a second device, a retry, or
/// someone else who knows the username and starts an exchange the account owner did not ask for.
/// Holding a single secret meant the newest arrival overwrote whatever an exchange already in
/// progress depended on, so one request from anyone was enough to stop someone else logging in.
/// Keeping the live secrets together lets those exchanges coexist: validation tries each until a
/// proof verifies.
///
/// The set is bounded because an anonymous caller decides how often it grows. Past the limit the
/// oldest secret is dropped, which still lets a caller who knows a username push a victim's secret
/// out: five login-initiate requests inside the window the victim spends typing their password are
/// enough, well under the per-IP limit that endpoint has. That is a smaller opening than the single
/// request it used to take, but it is not closed.
///
/// Closing it needs the secret bound to the exchange it belongs to rather than to the account --
/// returning an exchange id at login and having the client send it back with its proof, so a
/// stranger's exchange has nowhere to collide. That changes the shape of the login request, so
/// every client has to be updated together with the server before the bound here can go away.
///
/// Every member is guarded by the instance lock. Callers reach an instance through IMemoryCache,
/// which owns its lifetime; this type never expires anything itself.
/// </remarks>
public sealed class SrpEphemeralSet
{
    /// <summary>
    /// How many secrets one account may hold at once.
    /// </summary>
    /// <remarks>
    /// Above five simultaneous exchanges for a single account stops being a real usage pattern and
    /// starts being someone spending the server's memory. The limit also bounds validation, which
    /// walks the set.
    /// </remarks>
    public const int MaxSecretsPerAccount = 5;

    private readonly List<string> secrets = [];
    private readonly Lock gate = new();

    /// <summary>
    /// Adds a secret, dropping the oldest if the account is already at the limit.
    /// </summary>
    /// <param name="secret">The server ephemeral secret to store.</param>
    public void Add(string secret)
    {
        lock (this.gate)
        {
            this.secrets.Add(secret);

            while (this.secrets.Count > MaxSecretsPerAccount)
            {
                this.secrets.RemoveAt(0);
            }
        }
    }

    /// <summary>
    /// Returns the live secrets, newest first.
    /// </summary>
    /// <remarks>
    /// Newest first because the common case is an account with one exchange in flight, and after a
    /// retry the newest is the one the client is proving against. Returns a copy so callers can do
    /// the SRP work without holding the lock.
    /// </remarks>
    /// <returns>The stored secrets.</returns>
    public IReadOnlyList<string> GetSecrets()
    {
        lock (this.gate)
        {
            var snapshot = new string[this.secrets.Count];
            for (var i = 0; i < this.secrets.Count; i++)
            {
                snapshot[i] = this.secrets[this.secrets.Count - 1 - i];
            }

            return snapshot;
        }
    }

    /// <summary>
    /// Drops every secret for the account.
    /// </summary>
    /// <remarks>
    /// Called when an exchange finishes. It clears the whole set rather than the one secret that
    /// exchange used, which also ends any other exchange in flight for the same account — the
    /// behaviour this account already had when a single secret was stored.
    /// </remarks>
    public void Clear()
    {
        lock (this.gate)
        {
            this.secrets.Clear();
        }
    }
}
