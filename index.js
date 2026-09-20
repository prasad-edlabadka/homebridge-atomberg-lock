const { execFile, spawn } = require('child_process');
const http = require('http');
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
    this.daemonPort = this.config.daemonPort || 8765;
    this.autoLockDelay = this.config.autoLockDelay !== undefined ? Number(this.config.autoLockDelay) : 5;
    this.enableBattery = this.config.enableBattery !== undefined ? Boolean(this.config.enableBattery) : true;

    // Internal Lock State (1 = SECURED, 0 = UNSECURED)
    this.currentState = this.Characteristic.LockCurrentState.SECURED;
    this.targetState = this.Characteristic.LockTargetState.SECURED;
    this.isUnlocking = false;

    // Daemon Process Management
    this.daemonProcess = null;
    this.isShuttingDown = false;

    // Battery State
    this.batteryLevel = 100;
    this.statusLowBattery = this.Characteristic.StatusLowBattery.BATTERY_LEVEL_NORMAL;

    this.log.info(`[${this.name}] Initialized using script: ${this.scriptPath}`);
    this.log.info(`[${this.name}] Python interpreter: ${this.pythonPath}`);

    // Automatically spawn and supervise background micro-daemon
    this.startDaemon();

    // Register clean shutdown
    if (this.api && this.api.on) {
      this.api.on('shutdown', () => {
        this.isShuttingDown = true;
        this.stopDaemon();
      });
    }

    // 1. Accessory Information Service
    this.infoService = new this.Service.AccessoryInformation()
      .setCharacteristic(this.Characteristic.Manufacturer, 'Atomberg')
      .setCharacteristic(this.Characteristic.Model, 'SL1 Pro')
      .setCharacteristic(this.Characteristic.SerialNumber, this.mac || 'SL1-PRO')
      .setCharacteristic(this.Characteristic.FirmwareRevision, '1.1.0');

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

  startDaemon() {
    if (this.daemonProcess || this.isShuttingDown) {
      return;
    }

    const args = [this.scriptPath];

    if (this.mac) {
      args.push('-m', this.mac);
    }
    if (this.masterKey) {
      args.push('-k', this.masterKey);
    }
    if (this.salt) {
      args.push('-s', this.salt);
    }
    if (!this.mac && this.configPath) {
      args.push('-c', this.configPath);
    }
    if (this.adapter) {
      args.push('-a', this.adapter);
    }

    args.push('daemon', '--port', String(this.daemonPort));

    this.log.info(`[${this.name}] Starting auto background micro-daemon (port ${this.daemonPort})...`);

    try {
      this.daemonProcess = spawn(this.pythonPath, args, {
        stdio: ['ignore', 'pipe', 'pipe']
      });

      this.daemonProcess.stdout.on('data', (data) => {
        this.log.debug(`[Daemon stdout] ${data.toString().trim()}`);
      });

      this.daemonProcess.stderr.on('data', (data) => {
        this.log.debug(`[Daemon stderr] ${data.toString().trim()}`);
      });

      this.daemonProcess.on('exit', (code, signal) => {
        if (!this.isShuttingDown) {
          this.log.warn(`[${this.name}] Background daemon stopped (code: ${code}). Restarting in 5s...`);
          this.daemonProcess = null;
          setTimeout(() => this.startDaemon(), 5000);
        }
      });
    } catch (err) {
      this.log.error(`[${this.name}] Failed to auto-start daemon: ${err.message}`);
      this.daemonProcess = null;
    }
  }

  stopDaemon() {
    if (this.daemonProcess) {
      try {
        this.log.info(`[${this.name}] Terminating background daemon...`);
        this.daemonProcess.kill('SIGTERM');
      } catch (_) {}
      this.daemonProcess = null;
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

    // Asynchronously execute BLE unlock
    (async () => {
      const startTime = Date.now();
      try {
        this.log.info(`[${this.name}] Initiating fast unlock...`);
        const result = await this.executeAction('unlock');
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
        this.log.info(`[${this.name}] Door UNLOCKED in ${elapsed}s! Output: ${result.replace(/\n/g, ' ')}`);

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

  executeAction(action) {
    return new Promise((resolve, reject) => {
      // 1. Attempt ultra-fast background daemon first (sub-second unlock)
      const req = http.get(`http://127.0.0.1:${this.daemonPort}/${action}`, { timeout: 10000 }, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            return resolve(body);
          }
          try {
            const errObj = JSON.parse(body);
            if (errObj.message) return reject(new Error(errObj.message));
          } catch (_) {}
          reject(new Error(`Daemon returned HTTP ${res.statusCode}: ${body}`));
        });
      });

      req.on('error', () => {
        // Daemon not ready/listening -> Fallback to optimized CLI execution
        this.executeCli(action).then(resolve).catch(reject);
      });

      req.on('timeout', () => {
        req.destroy();
        this.executeCli(action).then(resolve).catch(reject);
      });
    });
  }

  executeCli(action) {
    return new Promise((resolve, reject) => {
      const args = [this.scriptPath];

      if (this.mac) {
        args.push('-m', this.mac);
      }
      if (this.masterKey) {
        args.push('-k', this.masterKey);
      }
      if (this.salt) {
        args.push('-s', this.salt);
      }

      if (!this.mac && this.configPath) {
        args.push('-c', this.configPath);
      }

      if (this.adapter) {
        args.push('-a', this.adapter);
      }

      args.push(action);

      execFile(this.pythonPath, args, { timeout: 20000 }, (error, stdout, stderr) => {
        if (error) {
          return reject(new Error(stderr || stdout || error.message));
        }
        if (stdout && stdout.toLowerCase().includes('failed to connect')) {
          return reject(new Error(stdout.trim()));
        }
        resolve(stdout.trim());
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

    this.executeAction('battery')
      .then((stdout) => {
        if (!stdout) return;
        const match = stdout.match(/Battery:\s*(\d+)%/i) || stdout.match(/"battery":\s*(\d+)/i) || stdout.match(/(\d+)%/);
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
