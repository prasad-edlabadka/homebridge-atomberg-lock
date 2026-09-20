const { execFile } = require('child_process');
const path = require('path');
const fs = require('fs');

module.exports = (api) => {
  api.registerAccessory('@prasad-edlabadkar/homebridge-atomberg-lock', 'AtombergLock', AtombergLockAccessory);
};

class AtombergLockAccessory {
  constructor(log, config, api) {
    this.log = log;
    this.config = config || {};
    this.api = api;

    this.Service = this.api.hap.Service;
    this.Characteristic = this.api.hap.Characteristic;

    this.name = this.config.name || 'Atomberg Smart Lock';

    // 1. Resolve Script Path (bundled within this plugin by default)
    this.scriptPath = this.config.scriptPath || path.join(__dirname, 'atomberg_cli.py');

    // 2. Resolve Python Path
    if (this.config.pythonPath) {
      this.pythonPath = this.config.pythonPath;
    } else if (fs.existsSync('/home/homebridge/venv/bin/python3')) {
      this.pythonPath = '/home/homebridge/venv/bin/python3';
    } else if (fs.existsSync(path.join(process.cwd(), 'venv/bin/python3'))) {
      this.pythonPath = path.join(process.cwd(), 'venv/bin/python3');
    } else {
      this.pythonPath = 'python3';
    }

    // 3. Credentials & Settings
    this.mac = this.config.mac || this.config.LOCK_MAC || '';
    this.masterKey = this.config.masterKey || this.config.STATIC_MASTER_KEY || '';
    this.salt = this.config.salt || this.config.LOCK_SALT || '';
    this.configPath = this.config.configPath || (fs.existsSync('/home/homebridge/config.json') ? '/home/homebridge/config.json' : '');
    this.adapter = this.config.adapter || '';
    this.autoLockDelay = this.config.autoLockDelay !== undefined ? Number(this.config.autoLockDelay) : 5;
    this.enableBattery = this.config.enableBattery !== undefined ? Boolean(this.config.enableBattery) : true;

    // Internal Lock State (1 = SECURED, 0 = UNSECURED)
    this.currentState = this.Characteristic.LockCurrentState.SECURED;
    this.targetState = this.Characteristic.LockTargetState.SECURED;
    this.isUnlocking = false;

    // Battery State
    this.batteryLevel = 100;
    this.statusLowBattery = this.Characteristic.StatusLowBattery.BATTERY_LEVEL_NORMAL;

    this.log.info(`[${this.name}] Initializing with script: ${this.scriptPath}`);
    this.log.info(`[${this.name}] Using Python path: ${this.pythonPath}`);

    // 1. Accessory Information Service
    this.infoService = new this.Service.AccessoryInformation()
      .setCharacteristic(this.Characteristic.Manufacturer, 'Atomberg')
      .setCharacteristic(this.Characteristic.Model, 'SL1 Pro')
      .setCharacteristic(this.Characteristic.SerialNumber, this.mac || 'SL1-PRO')
      .setCharacteristic(this.Characteristic.FirmwareRevision, '1.0.1');

    // 2. Lock Mechanism Service
    this.lockService = new this.Service.LockMechanism(this.name);

    this.lockService
      .setCharacteristic(this.Characteristic.LockCurrentState, this.Characteristic.LockCurrentState.SECURED)
      .setCharacteristic(this.Characteristic.LockTargetState, this.Characteristic.LockTargetState.SECURED);

    this.lockService
      .getCharacteristic(this.Characteristic.LockCurrentState)
      .onGet(this.getLockCurrentState.bind(this));

    this.lockService
      .getCharacteristic(this.Characteristic.LockTargetState)
      .onGet(this.getLockTargetState.bind(this))
      .onSet(this.setLockTargetState.bind(this));

    // 3. Optional Battery Service
    if (this.enableBattery) {
      this.batteryService = new this.Service.Battery(this.name + ' Battery');

      this.batteryService
        .setCharacteristic(this.Characteristic.BatteryLevel, 100)
        .setCharacteristic(this.Characteristic.StatusLowBattery, this.Characteristic.StatusLowBattery.BATTERY_LEVEL_NORMAL)
        .setCharacteristic(this.Characteristic.ChargingState, this.Characteristic.ChargingState.NOT_CHARGEABLE);

      this.batteryService
        .getCharacteristic(this.Characteristic.BatteryLevel)
        .onGet(this.getBatteryLevel.bind(this));

      this.batteryService
        .getCharacteristic(this.Characteristic.StatusLowBattery)
        .onGet(this.getStatusLowBattery.bind(this));

      // Periodically update battery every 2 hours
      setInterval(() => {
        this.updateBattery();
      }, 2 * 60 * 60 * 1000);

      // Initial battery check after 10s
      setTimeout(() => {
        this.updateBattery();
      }, 10000);
    }
  }

  getServices() {
    const services = [this.infoService, this.lockService];
    if (this.batteryService) {
      services.push(this.batteryService);
    }
    return services;
  }

  async getLockCurrentState() {
    return this.currentState;
  }

  async getLockTargetState() {
    return this.targetState;
  }

  async setLockTargetState(value) {
    this.log.info(`[${this.name}] Received Command: Set Target State to ${value === 0 ? 'UNSECURED (Unlock)' : 'SECURED (Lock)'}`);

    if (value === this.Characteristic.LockTargetState.SECURED) {
      this.targetState = this.Characteristic.LockTargetState.SECURED;
      this.currentState = this.Characteristic.LockCurrentState.SECURED;
      this.lockService.updateCharacteristic(this.Characteristic.LockCurrentState, this.currentState);
      this.lockService.updateCharacteristic(this.Characteristic.LockTargetState, this.targetState);
      return;
    }

    if (this.isUnlocking) {
      this.log.warn(`[${this.name}] Unlock already in progress, ignoring duplicate.`);
      return;
    }

    this.isUnlocking = true;
    this.targetState = this.Characteristic.LockTargetState.UNSECURED;
    this.lockService.updateCharacteristic(this.Characteristic.LockTargetState, this.targetState);

    // Asynchronously execute BLE unlock so HomeKit UI receives instant feedback
    (async () => {
      try {
        this.log.info(`[${this.name}] Initiating BLE unlock sequence...`);
        const stdout = await this.executeCliCommand('unlock');
        this.log.info(`[${this.name}] Output: ${stdout.trim().replace(/\n/g, ' ')}`);
        this.log.info(`[${this.name}] Door unlocked successfully!`);

        // Set state to Unlocked
        this.currentState = this.Characteristic.LockCurrentState.UNSECURED;
        this.lockService.updateCharacteristic(this.Characteristic.LockCurrentState, this.currentState);

        // Schedule auto-relock transition to match hardware clutch
        setTimeout(() => {
          this.log.info(`[${this.name}] Auto-relocking state (matching hardware 5s clutch).`);
          this.currentState = this.Characteristic.LockCurrentState.SECURED;
          this.targetState = this.Characteristic.LockTargetState.SECURED;
          this.lockService.updateCharacteristic(this.Characteristic.LockCurrentState, this.currentState);
          this.lockService.updateCharacteristic(this.Characteristic.LockTargetState, this.targetState);
          this.isUnlocking = false;
        }, this.autoLockDelay * 1000);

      } catch (err) {
        this.log.error(`[${this.name}] Unlock failed: ${err.message || err}`);
        this.currentState = this.Characteristic.LockCurrentState.SECURED;
        this.targetState = this.Characteristic.LockTargetState.SECURED;
        this.lockService.updateCharacteristic(this.Characteristic.LockCurrentState, this.currentState);
        this.lockService.updateCharacteristic(this.Characteristic.LockTargetState, this.targetState);
        this.isUnlocking = false;
      }
    })();
  }

  executeCliCommand(action) {
    return new Promise((resolve, reject) => {
      const args = [this.scriptPath];

      // Prefer explicit credentials if configured
      if (this.mac) {
        args.push('-m', this.mac);
      }
      if (this.masterKey) {
        args.push('-k', this.masterKey);
      }
      if (this.salt) {
        args.push('-s', this.salt);
      }

      // Fallback to config path
      if (!this.mac && this.configPath) {
        args.push('-c', this.configPath);
      }

      if (this.adapter) {
        args.push('-a', this.adapter);
      }

      args.push(action);

      this.log.info(`[${this.name}] Executing: ${this.pythonPath} ${args.join(' ')}`);

      execFile(this.pythonPath, args, { timeout: 30000 }, (error, stdout, stderr) => {
        if (error) {
          return reject(new Error(stderr || stdout || error.message));
        }
        if (stdout && stdout.toLowerCase().includes('failed to connect')) {
          return reject(new Error(stdout.trim()));
        }
        resolve(stdout);
      });
    });
  }

  async getBatteryLevel() {
    return this.batteryLevel;
  }

  async getStatusLowBattery() {
    return this.statusLowBattery;
  }

  updateBattery() {
    if (!this.enableBattery) return;

    this.executeCliCommand('battery')
      .then((stdout) => {
        if (!stdout) return;
        const match = stdout.match(/Battery:\s*(\d+)%/i) || stdout.match(/(\d+)%/);
        if (match && match[1]) {
          const level = parseInt(match[1], 10);
          if (!isNaN(level) && level >= 0 && level <= 100) {
            this.batteryLevel = level;
            this.statusLowBattery = level <= 20
              ? this.Characteristic.StatusLowBattery.BATTERY_LEVEL_LOW
              : this.Characteristic.StatusLowBattery.BATTERY_LEVEL_NORMAL;

            if (this.batteryService) {
              this.batteryService.updateCharacteristic(this.Characteristic.BatteryLevel, this.batteryLevel);
              this.batteryService.updateCharacteristic(this.Characteristic.StatusLowBattery, this.statusLowBattery);
            }
            this.log.info(`[${this.name}] Battery updated: ${this.batteryLevel}%`);
          }
        }
      })
      .catch((err) => {
        this.log.debug(`[${this.name}] Battery update check skipped: ${err.message}`);
      });
  }
}
