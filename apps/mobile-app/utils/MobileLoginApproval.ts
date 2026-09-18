import { Buffer } from 'buffer';
import QuickCrypto from 'react-native-quick-crypto';

/** Signs an exact mobile login approval using a key available only in the unlocked vault. */
export async function signMobileLoginApproval(requestId: string, publicKey: string, encryptedKey: string, privateKey: string): Promise<string> {
  const encoder = new TextEncoder();
  /** Hash an exact wire value to avoid differences in JSON serialization. */
  const hash = async (value: string): Promise<string> =>
    Buffer.from(await crypto.subtle.digest('SHA-256', encoder.encode(value))).toString('hex');
  const payload = `aliasvault:mobile-login:v1\n${requestId}\n${await hash(publicKey)}\n${await hash(encryptedKey)}`;
  const jwk = JSON.parse(privateKey);
  // The vault stores encryption JWK metadata; the same RSA parameters sign this purpose-bound proof.
  delete jwk.alg;
  delete jwk.use;
  jwk.ext = true;
  jwk.key_ops = ['sign'];
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSA-PSS', hash: 'SHA-256' }, true, ['sign']);
  // QuickCrypto's WebCrypto sign does not implement RSA-PSS; its native OpenSSL signer does.
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', key);
  const signer = QuickCrypto.createSign('SHA256');
  signer.update(payload, 'utf8');
  const signature = signer.sign({
    key: new Uint8Array(pkcs8),
    format: 'der',
    type: 'pkcs8',
    padding: QuickCrypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32,
  });
  return Buffer.from(signature as Uint8Array).toString('base64');
}
