import Homey from 'homey';
import TPLink from '../../lib/tplinkApi';
import CryptoUtil from '../../lib/cryptoUtil';

class RouterDriver extends Homey.Driver {

  async onPair(session) {
    const router: TPLink = new TPLink(this);

    let ipAddress = '';
    let password = '';

    session.setHandler('login', async (data) => {
      const connected = await router.connect(data.username, data.password);
      if (connected) {
        ipAddress = data.username;
        password = data.password;
      }

      return connected;
    });

    session.setHandler('list_devices', async () => {
      const deviceInfo = await router.getDeviceInfo();
      const status = await router.getAllStatus()
        .catch(() => {
          return [];
        });

      return [{
        name: deviceInfo.model,
        data: {
          id: status.lan_macaddr,
        },
        settings: {
          ip_address: ipAddress,
          password: CryptoUtil.encrypt(password, Homey.env.AES_SECRET),
        },
      }];
    });
  }

}

module.exports = RouterDriver;
