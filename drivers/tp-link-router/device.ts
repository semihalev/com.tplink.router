/* eslint-disable @typescript-eslint/no-explicit-any */

// import Homey from 'homey';
import Homey from 'homey';
import TPLink from '../../lib/tplinkApi';
import CryptoUtil from '../../lib/cryptoUtil';

class RouterDevice extends Homey.Device {

  static SensorCapabilities = [
    'wan_ipv4_ipaddr',
    'wan_ipv4_uptime',
    'lan_ipv4_ipaddr',
    'connected_clients',
    'cpu_usage',
    'mem_usage',
    'alarm_wan',
  ];

  static ButtonCapabilities = [
    'led_onoff',
    'reboot',
  ];

  router: TPLink = new TPLink(this);
  connected: boolean = false;
  status: any = null;
  statusInterval: any = null;
  loggingIn: boolean = false;
  clients: any[] = [];
  wanStatus: string = '';

  ip_address: string = '';
  password: string = '';

  clientStateFlow!: Homey.FlowCardTriggerDevice;
  wanStateFlow!: Homey.FlowCardTriggerDevice;

  async onInit() {
    const settings = this.getSettings();

    this.ip_address = settings.ip_address;
    this.password = CryptoUtil.decrypt(settings.password, Homey.env.AES_SECRET);

    this.connected = await this.router.connect(this.ip_address, this.password).catch((e) => {
      this.error(e);
      return false;
    });

    await this.addSensorCapabilities();
    await this.updateSensorCapabilities();

    await this.addButtonCapabilities();
    await this.updateButtonCapabilities();
    await this.registerButtonCapabilityListeners();

    await this.updateClients();
    await this.updateWanStatus();

    this.registerActionFlows();
    this.registerConditionFlows();
    this.registerTriggerFlows();

    this.startIntervals();
  }

  async addSensorCapabilities() {
    if (this.hasCapability('alarm_generic.wan')) {
      await this.removeCapability('alarm_generic.wan');
    }
    for (const capability of RouterDevice.SensorCapabilities) {
      if (!this.hasCapability(capability)) {
        await this.addCapability(capability);
      }
    }
  }

  async updateSensorCapabilities() {
    this.status = await this.router.getAllStatus().catch((error) => Promise.resolve(error));
    if (this.status.stack && this.status.message) {
      await this.startLoginInterval(this.status);
      return;
    }

    for (const capability of RouterDevice.SensorCapabilities) {
      if (this.hasCapability(capability)) {
        let value: any = this.status[capability];
        if (capability === 'wan_ipv4_uptime') {
          value = this.secondsToDuration(this.status[capability]);
        }
        if (capability === 'mem_usage' || capability === 'cpu_usage') {
          value = this.status[capability] * 100;
        }
        if (capability === 'connected_clients') {
          value = this.status.access_devices_wireless_host.length;
          if (this.status.access_devices_wired) {
            value += this.status.access_devices_wired.length;
          }
        }
        if (capability === 'alarm_wan') {
          value = this.wanStatus !== 'connected' && this.wanStatus !== '';
        }
        await this.setCapabilityValue(capability, value);
      }
    }
  }

  async addButtonCapabilities() {
    for (const capability of RouterDevice.ButtonCapabilities) {
      if (!this.hasCapability(capability)) {
        await this.addCapability(capability);
      }
    }
  }

  async updateButtonCapabilities() {
    for (const capability of RouterDevice.ButtonCapabilities) {
      if (this.hasCapability(capability)) {
        let value: boolean = false;
        if (capability === 'led_onoff') {
          value = await this.router.getLEDStatus().catch(() => {
            return false;
          });
        }
        await this.setCapabilityValue(capability, value);
      }
    }
  }

  async registerButtonCapabilityListeners() {
    this.registerCapabilityListener('led_onoff', async (value) => {
      await this.router.setLEDStatus(value).catch(this.error);
    });

    this.registerCapabilityListener('reboot', async () => {
      await this.router.reboot().catch(this.error);
      await this.startLoginInterval(new Error('Device restarting...'));
    });
  }

  async updateClients() {
    const lastClients = this.clients;

    try {
      this.clients = await this.router.getConnectedDevices();
    } catch (e) {
      this.error(e);
      return;
    }

    for (const client of this.clients) {
      if (lastClients.length > 0) {
        if (!lastClients.find(obj => {
          return obj.mac === client.mac;
        })) {
          const tokens = {
            name: client.name,
            ipaddr: client.ipaddr,
            mac: client.mac,
          };
          await this.clientStateFlow.trigger(this, tokens, {status: 'online', client: tokens});
        }
      }
    }

    if (lastClients.length > 0) {
      for (const client of lastClients) {
        if (!this.clients.find(obj => {
          return obj.mac === client.mac;
        })) {
          const tokens = {
            name: client.name,
            ipaddr: client.ipaddr,
            mac: client.mac,
          };
          await this.clientStateFlow.trigger(this, tokens, {status: 'offline', client: tokens});
        }
      }
    }
  }

  async updateWanStatus() {
    try {
      const status = await this.router.getInternetStatus();
      if (this.wanStatus === '') {
        this.wanStatus = status.wan_internet_status;
        return;
      }

      if (this.wanStatus !== status.wan_internet_status) {
        await this.wanStateFlow.trigger(this, {status: status.wan_internet_status === 'connected'}, {});
      }

      this.wanStatus = status.wan_internet_status;
    } catch (e) {
      this.error(e);
    }
  }

  registerActionFlows() {
    const rebootFlow = this.homey.flow.getActionCard('reboot');
    rebootFlow.registerRunListener(async () => {
      await this.router.reboot();
      await this.startLoginInterval(new Error('Device restarting...'));
    });

    const ledStatusFlow = this.homey.flow.getActionCard('led_status');
    ledStatusFlow.registerRunListener(async (args) => {
      await this.router.setLEDStatus(args.state);
      await this.setCapabilityValue('led_onoff', args.state);
    });
  }

  registerConditionFlows() {
    const clientIsConnected = this.homey.flow.getConditionCard('client_is_online');
    clientIsConnected.registerRunListener(async (args) => {
      await this.updateClients();
      if (this.clients.find(client => client.mac === args.client.mac)) {
        return true;
      }
      return false;
    });

    clientIsConnected.registerArgumentAutocompleteListener('client', async (query) => {
      const filteredClients = this.clients.filter((client) => {
        const search = query.toLowerCase();

        return client.mac.toLowerCase().includes(search) ||
        client.name.toLowerCase().includes(search) ||
        client.ipaddr.toLowerCase().includes(search);
      });

      const results = [
        ...filteredClients.map(client => ({name: client.name, mac: client.mac, description: client.mac})),
      ];

      return results;
    });
  }

  registerTriggerFlows() {
    this.clientStateFlow = this.homey.flow.getDeviceTriggerCard('client_state_changed');
    this.wanStateFlow = this.homey.flow.getDeviceTriggerCard('wan_state_changed');

    this.clientStateFlow.registerRunListener(async (args, state) => {
      return args.status === state.status && args.client.mac === state.client.mac;
    });

    this.clientStateFlow.registerArgumentAutocompleteListener('client', async (query) => {
      const filteredClients = this.clients.filter((client) => {
        const search = query.toLowerCase();

        return client.mac.toLowerCase().includes(search) ||
        client.name.toLowerCase().includes(search) ||
        client.ipaddr.toLowerCase().includes(search);
      });

      const results = [
        ...filteredClients.map(client => ({name: client.name, mac: client.mac, description: client.mac})),
      ];

      return results;
    });
  }

  startIntervals() {
    this.statusInterval = this.homey.setInterval(async () => {
      if (this.connected) {
        await this.updateSensorCapabilities();
        await this.updateButtonCapabilities();
        await this.updateClients();
        await this.updateWanStatus();
      }
    }, 15 * 1000);
  }

  async startLoginInterval(error: any) {
    if (this.loggingIn) {
      return;
    }

    this.connected = false;
    this.error(error.message);

    if (this.getAvailable()) {
      await this.setUnavailable(`Disconnected: ${error.message}`);
    }

    this.loggingIn = true;
    await this.setWarning('Trying connect to the router...');

    this.homey.setTimeout(async () => {
      this.connected = await this.router.connect(this.ip_address, this.password).catch((e) => {
        this.error(e.message);
        return false;
      });

      if (this.connected && !this.getAvailable()) {
        await this.setAvailable();
      }

      this.loggingIn = false;
      await this.unsetWarning();

      if (!this.connected) {
        await this.startLoginInterval(error);
      }
    }, 2 * 60 * 1000);
  }

  clearIntervals() {
    this.homey.clearInterval(this.statusInterval);
  }

  onDeleted(): void {
    this.clearIntervals();
  }

  secondsToDuration(seconds: number) {
    seconds = Number(seconds);
    const d = Math.floor(seconds / (3600*24));
    const h = Math.floor(seconds % (3600*24) / 3600);
    const m = Math.floor(seconds % 3600 / 60);
    // const s = Math.floor(seconds % 60);

    const dDisplay = d > 0 ? d + 'd' : '';
    const hDisplay = h > 0 ? ' ' + h + 'h' : '';
    const mDisplay = m > 0 ? ' ' + m + 'm' : '';

    return dDisplay + hDisplay + mDisplay;
  }
}

module.exports = RouterDevice;
