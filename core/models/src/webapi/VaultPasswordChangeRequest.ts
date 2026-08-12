import { Vault } from "./Vault";

/**
 * Represents a request to change the users password including a new vault that is encrypted with the new password.
 */
export type VaultPasswordChangeRequest = Vault & {
    currentClientPublicEphemeral: string;
    currentClientSessionProof: string;
    newPasswordSalt: string;
    newPasswordVerifier: string;
    /**
     * The Argon2id parameters the new verifier was derived with. The vault can only be opened
     * again with the parameters its key was derived under, so the server records these rather
     * than its own defaults. Optional: a server that predates the fields ignores them.
     */
    newPasswordEncryptionType?: string;
    newPasswordEncryptionSettings?: string;
}
