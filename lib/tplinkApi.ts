//
// TP-Link API by Jason Grimard 2023
// Tested and working with Archer AX6000
// Based on prior API work by Michal Chvila
//

import * as crypto from 'crypto';
import axios from 'axios';

export default class TPLink {

  private HEADERS = { // default headers for all requests
    Accept: 'application/json, text/javascript, */*; q=0.01',
    'User-Agent': 'Homey TP-Link Access Control',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'X-Requested-With': 'XMLHttpRequest',
  };

  private token: string = ''; // stok token from router
  private rsaPublicKeyPw!: crypto.KeyObject; // (n, e) RSA public key from router for encrypting the password
  private rsaPublicKeyAuth!: crypto.KeyObject;
  private rsaKeyAuth: string[] = []; // (n, e, seq) RSA public key from router for encrypting signature
  private md5HashPw: string = ''; // md5 of username and password, used to sign data, not login
  private aesKey: string[] = []; // random AES key for encrypting the body of the request and decrypting the response
  private cookies: Map<string, string> = new Map(); // cookies from login response
  public loggingIn: boolean = false; // true if currently logging in, false if not

  private ip: string = '';
  private password: string = '';

  private log:any;
  private error:any;
  private homey:any;

  constructor(initatorClass:any) {
    this.log = initatorClass.log;
    this.error = initatorClass.error;
    this.homey = initatorClass.homey;
  }

  // Create URL from ip address, endpoint, form, and STOK token
  private getURL(endpoint: string, form: string): string {
    // this.log(`'Returning url: http://${this.ip}/cgi-bin/luci/;stok=${this.token}/${endpoint}?form=${form}`);
    return `http://${this.ip}/cgi-bin/luci/;stok=${this.token}/${endpoint}?form=${form}`;
  }

  public async connect(ip: string, password: string): Promise<boolean> {
    if (this.loggingIn) {
      this.log('Already logging in, waiting for login to complete');
      // wait for login to complete before returning
      // if this takes more than 10 seconds, something is wrong and we should change the loggingIn flag to false
      let count = 0;
      while (this.loggingIn) {
        // sleep for 100ms
        await new Promise((resolve) => this.homey.setTimeout(resolve, 100));
        count++;
        if (count > 100) {
          this.error('Error logging in, login is taking too long');
          this.loggingIn = false;
          return Promise.reject(new Error('Error logging in, login is taking too long'));
        }
      }
      return true;
    }
    this.ip = ip;
    this.password = password;
    this.loggingIn = true;
    this.token = ''; // clear the token
    // hash the username and password. The username is always admin
    this.md5HashPw = this.hashPw('admin', this.password);
    // get the public rsa key for encrypting the password
    this.rsaPublicKeyPw = await this.getRSAPublicKeyPassword();
    // get the public rsa key for encrypting the auth token / signature
    this.rsaKeyAuth = await this.getRSAPublicKeyAuth();
    // generate random AES key
    this.aesKey = this.generateAESKey();
    // encrypt the password
    const encryptedPassword = this.encryptPassword(this.password);
    // authenticate and get the auth token
    try {
      this.token = await this.login(encryptedPassword);
      this.log('Successfully connected to TPLink, token:', this.token);
    } catch (error) {
      this.loggingIn = false;
      throw error;
    }
    this.loggingIn = false;
    return true;
  }

  public async logout(): Promise<boolean> {
    const url = this.getURL('admin/system', 'logout');
    const data = {
      operation: 'write',
    };
    const response = await this.request(url, data, true);
    if (response.success === true) {
      this.log('Successfully logged out of TPLink');
      return true;
    }
    this.error('Error logging out of TPLink', response);
    return false;
  }

  // get list of connected devices that are available
  public async getConnectedDevices(): Promise<any[]> {
    const url = this.getURL('admin/access_control', 'black_devices');
    const data = {
      operation: 'load',
    };
    const response = await this.request(url, data, true);
    if (response.success === true) {
      if (Object.keys(response.data).length > 0) { // test for empty object
        return response.data;
      }

      this.log('No connected devices found');
      return [];
    }
    throw new Error(`Error getting connected devices: ${JSON.stringify(response)}`);
  }

  public async getSmartNetwork(): Promise<any[]> {
    const url = this.getURL('admin/smart_network', 'game_accelerator');
    const data = {
      operation: 'loadDevice', // or loadSpeed need to be compare
    };
    const response = await this.request(url, data, true);
    if (response.success === true) {
      this.log(response.data);
      if (Object.keys(response.data).length > 0) { // test for empty object
        return response.data;
      }

      this.log('No connected devices found');
      return [];
    }
    throw new Error(`Error getting smart network: ${JSON.stringify(response)}`);
  }

  // get all information.
  public async getAllStatus(): Promise<any> {
    const url = this.getURL('admin/status', 'all');
    const data = {
      operation: 'load',
    };
    const response = await this.request(url, data, true);
    if (response.success === true) {
      return response.data;
    }
    throw new Error(`Error getting status information: ${JSON.stringify(response)}`);
  }

  // get internet information.
  public async getInternetStatus(): Promise<any> {
    const url = this.getURL('admin/status', 'internet');
    const data = {
      operation: 'load',
    };
    const response = await this.request(url, data, true);
    if (response.success === true) {
      return response.data;
    }
    throw new Error(`Error getting internet status: ${JSON.stringify(response)}`);
  }

  // get client status information.
  public async getClientStatus(): Promise<any> {
    const url = this.getURL('admin/status', 'client_status');
    const data = {
      operation: 'load',
    };
    const response = await this.request(url, data, true);
    if (response.success === true) {
      return response.data;
    }
    throw new Error(`Error getting clients status: ${JSON.stringify(response)}`);
  }

  // get system information.
  public async getSystem(): Promise<any> {
    const url = this.getURL('admin/system', 'sysmode');
    const data = {
      operation: 'read',
    };
    const response = await this.request(url, data, true);
    if (response.success === true) {
      return response.data;
    }
    throw new Error(`Error getting system information: ${JSON.stringify(response)}`);
  }

  // get router status information.
  public async getRouterStatus(): Promise<any> {
    const url = this.getURL('admin/status', 'router');
    const data = {
      operation: 'read',
    };
    const response = await this.request(url, data, true);
    if (response.success === true) {
      return response.data;
    }
    throw new Error(`Error getting router status: ${JSON.stringify(response)}`);
  }

  // get device information.
  public async getDeviceInfo(): Promise<any> {
    const url = this.getURL('admin/cloud_account', 'get_deviceInfo');
    const data = {
      operation: 'read',
    };
    const response = await this.request(url, data, true);
    if (response.success === true) {
      return response.data;
    }
    return { model: 'TP-Link Router' };
  }

  // reboot the router
  public async reboot(): Promise<boolean> {
    this.log('Device restarting...');
    const url = this.getURL('admin/system', 'reboot');
    const data = {
      operation: 'write',
    };
    const response = await this.request(url, data, true);
    if (response.success === true) {
      return true;
    }
    return false;
  }

  // get list of blocked devices return mac address only.  Index is used when unblocking devices.
  public async getBlockedDevices(): Promise<string[]> {
    const url = this.getURL('admin/access_control', 'black_list');
    const data = {
      operation: 'load',
    };
    const response = await this.request(url, data, true);
    if (response.success === true) {
      const devices: string[] = [];
      if (Object.keys(response.data).length > 0) { // test for empty object
        for (const device of response.data) {
          this.log(`Found blocked device named ${device.name} with mac address ${device.mac}`);
          devices.push(device.mac);
        }
      }
      return devices;
    }
    throw new Error(`Error getting blocked devices: ${JSON.stringify(response)}`);
  }

  // block device by mac address
  public async blockDevice(macAddress: string): Promise<boolean> {
    const url = this.getURL('admin/access_control', 'black_devices');
    const deviceData = {
      mac: macAddress,
      host: 'NOT HOST',
    };
    // TP-Link uses a weird encoding for the device data
    let deviceDataJson = JSON.stringify(deviceData);
    // wrap device data json in square brackets
    deviceDataJson = `[${deviceDataJson}]`;
    const encodedDeviceData = encodeURIComponent(deviceDataJson);
    const data = {
      operation: 'block',
      data: [encodedDeviceData],
    };
    const response = await this.request(url, data, true);
    if (response.success === true) {
      this.log(`Successfully blocked device with mac address ${macAddress}`);
    } else {
      this.error('Error blocking device', response);
      return Promise.reject(new Error('Error blocking device'));
    }
    return true;
  }

  // unblock device by mac address
  public async unblockDevice(macAddress: string): Promise<boolean> {
    const url = this.getURL('admin/access_control', 'black_list');
    const blockedDevices = await this.getBlockedDevices();
    const index = blockedDevices.indexOf(macAddress);
    if (index > -1) {
      const data = {
        key: 'anything',
        index: index.toString(),
        operation: 'remove',
      };
      const response = await this.request(url, data, true);
      if (response.success === true) {
        this.log(`Successfully unblocked device with mac address ${macAddress}`);
        return true;
      }
      this.error('Error unblocking device', response);
      return Promise.reject(new Error('Error unblocking device'));
    }
    this.log(`Device with mac address ${macAddress} not found in blocked devices`);
    return false;
  }

  // get LED status
  public async getLEDStatus(): Promise<boolean> {
    const url = this.getURL('admin/ledgeneral', 'setting');
    const data = {
      operation: 'read',
    };
    const response = await this.request(url, data, true);
    if (response.success === true) {
      return Promise.resolve(response.data.enable === 'on');
    }
    this.error('Error getting LED status', response);
    return Promise.reject(new Error('Error getting LED status'));
  }

  // get Login Status
  public async getLoggedInStatus(): Promise<boolean> {
    const url = this.getURL('admin/ledgeneral', 'setting');
    const data = {
      operation: 'read',
    };
    const response = await this.request(url, data, true);
    if (response.success === true) {
      return true;
    }
    return false;
  }

  // set LED status true = on, false = off
  // router only allows toggling, so we need to get the current status first
  public async setLEDStatus(status: boolean): Promise<boolean> {
    this.log(`Setting LED status to ${status}`);
    const currentStatus = await this.getLEDStatus();
    if (currentStatus !== status) {
      const url = this.getURL('admin/ledgeneral', 'setting');
      const data = {
        operation: 'write',
        led_status: 'toggle',
      };
      const response = await this.request(url, data, true);
      if (response.success === true) {
        return Promise.resolve(true);
      }
      this.error('Error getting LED status', response);
      return Promise.reject(new Error('Error getting LED status'));
    }
    this.log(`LED status is already ${status}`);
    return Promise.resolve(true);
  }

  // login to the router
  // return value: (stok token) token for authentication
  private async login(encryptedPassword: string, forceLogin = true): Promise<string> {
    const url = this.getURL('login', 'login');
    const data = {
      operation: 'login',
      password: encryptedPassword,
    };
    if (forceLogin) {
      data['confirm'] = 'true';
    }
    const response = await this.request(url, data, true, true);
    if (response.success === true) {
      return response.data.stok;
    }
    throw new Error(`Login Error (Probably wrong password): ${JSON.stringify(response.data)}`);
  }

  // Returns an object containing the response.data from the router
  async request(url: string, data: any, encrypt = false, isLogin = false): Promise<any> {
    let formData: any;
    if (encrypt) { // encrypt the body data
      const dataStr = this.formatBodyToEncrypt(data);
      // generate AES cipher
      if (this.aesKey === undefined) {
        this.error('AES key not found');
      }

      const cipher = crypto.createCipheriv('AES-128-CBC', this.aesKey[0], this.aesKey[1]);
      let encryptedDataStr = cipher.update(dataStr, 'utf8', 'base64');
      encryptedDataStr += cipher.final('base64');
      cipher.destroy();

      // get encrypted signature
      const signature = this.getSignature(encryptedDataStr.length, isLogin);
      // signature needs to go first in the form
      formData = {
        sign: signature,
        data: encryptedDataStr,
      };
    } else { // not encrypted, just send the body data
      formData = data;
    }
    const bodyParams = new URLSearchParams();
    Object.keys(formData).forEach((key) => {
      bodyParams.append(key, formData[key]);
    });
    // add cookies to temp headers.  Don't append to this.HEADERS
    const tempHeaders = this.HEADERS;
    if (this.cookies.size > 0) {
      let cookieStr = '';
      for (const [cookieName, cookieValue] of this.cookies) {
        cookieStr += `${cookieName}=${cookieValue}; `;
      }
      tempHeaders['Cookie'] = cookieStr;
    }

    const options = {
      url,
      method: 'POST',
      headers: this.HEADERS,
      // timeout: 5000,
      data: bodyParams,
    };

    const response = await axios.request(options)
      .then((response) => {
        return response;
      }).catch((error) => {
        this.error(error.message);
        throw error;
      });

    const responseData = response.data;
    const responseCookies = response.headers['set-cookie'];

    // this.log('Received response headers from TPLink', response.headers);
    // parse cookies
    if (responseCookies !== undefined) {
      // this.log('Received cookies from TPLink', responseCookies);
      for (const cookie of responseCookies) {
        const cookieName = cookie.split('=')[0];
        const cookieValue = cookie.split('=')[1].split(';')[0]; // remove anything after the first ';'
        this.cookies.set(cookieName, cookieValue);
      }
    }
    if (encrypt) { // decrypt the response
      const decipher = crypto.createDecipheriv('AES-128-CBC', this.aesKey[0], this.aesKey[1]);

      let responseStr = '';
      try {
        responseStr += decipher.update(responseData.data, 'base64', 'utf8');
        responseStr += decipher.final('utf8');
        decipher.destroy();
      } catch (error) {
        return { data: { error: 'Decryption failed, forced logout.' } };
      }

      try { // try to parse the response as json
        return JSON.parse(responseStr);
      } catch (error) { // if it fails, return the response as an object with data
        this.log('Response is not json, returning as an object with data');
        return { data: responseStr };
      }
    } else { // not encrypted, just return the responseData
      return responseData;
    }
  }

  // concatinates a variable number of strings and return md5 hash
  private hashPw(...args: string[]): string {
    let result = '';
    for (const arg of args) {
      result += arg;
    }
    return crypto.createHash('md5').update(result).digest('hex');
  }

  // get the public rsa key from the router
  // return value: (n, e) RSA public key for encrypting the password as array of two strings
  private async getRSAPublicKeyPassword(): Promise<crypto.KeyObject> {
    const url = this.getURL('login', 'keys');
    const data = {
      operation: 'read',
    };
    const response = await this.request(url, data);
    if (response.success === true) {
      const publicKey = crypto.createPublicKey({
        key: {
          n: Buffer.from(response.data.password[0], 'hex').toString('base64'),
          e: Buffer.from(response.data.password[1], 'hex').toString('base64'),
          kty: 'RSA',
        },
        format: 'jwk',
      });

      return publicKey;
    }
    throw new Error(`Error getting RSA public key for password from TPLink: ${JSON.stringify(response)}`);
  }

  // get the public rsa key from the router
  // return value: (n, e, seq) RSA public key for encrypting the signature
  private async getRSAPublicKeyAuth(): Promise<string[]> {
    const url = this.getURL('login', 'auth');
    const data = {
      operation: 'read',
    };
    const response = await this.request(url, data);
    if (response.success === true) {
      const authPublicKey = response.data.key;
      authPublicKey.push(response.data.seq.toString());

      this.rsaPublicKeyAuth = crypto.createPublicKey({
        key: {
          n: Buffer.from(authPublicKey[0], 'hex').toString('base64'),
          e: Buffer.from(authPublicKey[1], 'hex').toString('base64'),
          kty: 'RSA',
        },
        format: 'jwk',
      });

      // this.log.debug('Successfully got RSA public key for signature from TPLink', authPublicKey);
      return authPublicKey;
    }
    throw new Error(`Error getting RSA public key for Auth from TPLink: ${JSON.stringify(response)}`);
  }

  // generate a random AES key
  private generateAESKey(): string[] {
    const keyLen = 16 / 2;
    const IVLen = 16 / 2;
    const key = crypto.randomBytes(keyLen);
    const iv = crypto.randomBytes(IVLen);
    return [key.toString('hex'), iv.toString('hex')];
  }

  // encrypt the password using RSA public key
  private encryptPassword(password: string): string {
    const encryptedData = crypto.publicEncrypt({
      key: this.rsaPublicKeyPw,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    }, Buffer.from(password));
    return encryptedData.toString('hex');
  }

  // Generate encrypted signature for the request
  private getSignature(bodyDataLength: number, isLogin = false): string {
    // aesKey:         Generated pseudo-random AES key (CBC, PKCS7) [key, iv]
    // rsaKeyAuth:     RSA public key from the TP-Link API endpoint (login?form=auth) [key, iv, sequence]
    // md5HashPw:      MD5 hash of the username+password as string, only used for signing, not login
    // bodyDataLength: Gength of the encrypted body message
    // isLogin:        Set to True for login request
    let signData = '';
    if (isLogin) {
      // on login we also send our AES key, which is used for end to end encryption
      const aesKeyString = `k=${this.aesKey[0]}&i=${this.aesKey[1]}`;
      signData = `${aesKeyString}&h=${this.md5HashPw}&s=${parseInt(this.rsaKeyAuth[2], 10) + bodyDataLength}`;
    } else { // not login
      signData = `h=${this.md5HashPw}&s=${parseInt(this.rsaKeyAuth[2], 10) + bodyDataLength}`;
    }

    let signature = '';
    const chunkSize = 53;
    let position = 0;
    while (position < signData.length) {
      const chunk = Buffer.from(signData.slice(position, position + chunkSize));
      signature += crypto.publicEncrypt({
        key: this.rsaPublicKeyAuth,
        padding: crypto.constants.RSA_PKCS1_PADDING,
      }, chunk).toString('hex');
      position += chunkSize;
    }
    return signature;
  }

  private formatBodyToEncrypt(data: any): string {
    // format form data into a string
    const dataArr: string[] = [];
    for (const [attr, value] of Object.entries(data)) {
      dataArr.push(`${attr}=${value}`);
    }
    return dataArr.join('&');
  }

}
