import * as crypto from 'crypto';

export default class CryptoUtil {
  static ALGORITHM: string = 'aes-256-cbc';

  static encrypt(plainText: string, key: string): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(CryptoUtil.ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(plainText), cipher.final()]);

    return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
  }

  static decrypt(encryptedText: string, key: string): string {
    const parts = encryptedText.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const encryptedData = Buffer.from(parts[1], 'hex');
    const decipher = crypto.createDecipheriv(CryptoUtil.ALGORITHM, key, iv);
    const decryptedText = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

    return decryptedText.toString();
  }
}