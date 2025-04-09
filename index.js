/*
 * NodeJS <-> NMAP interface
 * Author:  John Horton
 * Purpose: Create an interface for NodeJS applications to make use of NMAP installed on the local system.
 *
 * Fix 2020:
 *   Added check for undefined to portItem.service
 */

const child_process = require('child_process');
const spawn = child_process.spawn;
const EventEmitter = require('events').EventEmitter;
const Queue = require('queued-up');
const xml2js = require('xml2js');


/**
 *
 * @param {*} xmlInput
 * @param {*} onFailure
 * @return {host[]} - Array of hosts
 */
function convertRawJsonToScanResults(xmlInput) {
  let tempHostList = [];

  if (!xmlInput.nmaprun.host) {
    // onFailure("There was a problem with the supplied NMAP XML");
    return tempHostList;
  };

  xmlInput = xmlInput.nmaprun.host;

  tempHostList = xmlInput.map((host) => {
    const newHost = {
      hostname: null,
      ip: null,
      mac: null,
      openPorts: null,
      osNmap: null,
    };

    // Get hostname
    if (host.hostnames && host.hostnames[0] !== '\r\n' && host.hostnames[0] !== '\n') {
      newHost.hostname = host.hostnames[0].hostname[0].$.name;
    }

    // get addresses
    host.address.forEach((address) => {
      const addressType = address.$.addrtype;
      const addressAdress = address.$.addr;
      const addressVendor = address.$.vendor;

      if (addressType === 'ipv4') {
        newHost.ip = addressAdress;
      } else if (addressType === 'mac') {
        newHost.mac = addressAdress;
        newHost.vendor = addressVendor;
      }
    });

    // get ports
    if (host.ports && host.ports[0].port) {
      const portList = host.ports[0].port;

      const openPorts = portList.filter((port) => {
        // CW@2020 UPDATE 4.0.2 - less strict test for open port (may contain 'open|filtered')
        return (/^open/i.test(port.state[0].$.state));
      });


      newHost.openPorts = openPorts.map((portItem) => {
        // console.log(JSON.stringify(portItem, null, 4))

        const port = parseInt(portItem.$.portid);
        const protocol = portItem.$.protocol;

        const portObject = {};

        // CW@2020 UPDATE 4.0.1 - check for empty service
        // some ports don't have a service xml tag
        if (portItem.service) {
          const service = portItem.service[0].$.name;
          const tunnel = portItem.service[0].$.tunnel;
          const method = portItem.service[0].$.method;
          // CW@2021 UPDATE 4.0.3 - product instead of tunnel
          const product = portItem.service[0].$.product;
          const state = portItem.state[0].$.state;

          if (service) portObject.service = service;
          if (tunnel) portObject.tunnel = tunnel;
          if (method) portObject.method = method;
          if (product) portObject.product = product;
          if (state) portObject.state = state;
        }

        if (port) portObject.port = port;
        if (protocol) portObject.protocol = protocol;

        return portObject;
      });
    }

    if (host.os && host.os[0].osmatch && host.os[0].osmatch[0].$.name) {
      newHost.osNmap = host.os[0].osmatch[0].$.name;
    }
    return newHost;
  });

  return tempHostList;
}


class NmapScan extends EventEmitter {
  constructor(range, inputArguments, {sudo, sudoArgs} = {}) {
    super();
    this.command = [];
    this.nmapoutputXML = '';
    this.timer;
    this.range = [];
    this.arguments = ['-oX', '-'];
    this.rawData = '';
    this.rawJSON;
    this.child;
    this.cancelled = false;
    this.scanTime = 0;
    this.error = null;
    this.scanResults;
    this.scanTimeout = 0;

    // CW@2020 UPDATE 4.0.2 - sudo feature (includes constructor parameters)
    if (sudo) {
      this.arguments.unshift(nmap.nmapLocation);

      if (sudoArgs) {
        this.arguments.unshift(...sudoArgs);
      }
      nmap.nmapLocation = sudo;
    }

    this.commandConstructor(range, inputArguments);
    this.initializeChildProcess();
  }

  startTimer() {
    this.timer = setInterval(() => {
      this.scanTime += 10;
      if (this.scanTime >= this.scanTimeout && this.scanTimeout !== 0) {
        this.killChild();
      }
    }, 10);
  }

  stopTimer() {
    clearInterval(this.timer);
  }

  commandConstructor(range, additionalArguments) {
    if (additionalArguments) {
      if (!Array.isArray(additionalArguments)) {
        additionalArguments = additionalArguments.split(' ');
      }
      this.command = this.arguments.concat(additionalArguments);
    } else {
      this.command = this.arguments;
    }

    if (!Array.isArray(range)) {
      range = range.split(' ');
    }
    this.range = range;
    this.command = this.command.concat(this.range);
  }

  killChild() {
    if (this.cancelled === true) {
      // CW@2021: Fix infinite recursion on timeout of nmap command
      return;
    }

    this.cancelled = true;
    if (this.child) {
      this.child.kill();
    }
  }

  initializeChildProcess() {
    this.startTimer();
    this.child = spawn(nmap.nmapLocation, this.command);
    process.on('SIGINT', this.killChild);
    process.on('uncaughtException', this.killChild);
    process.on('exit', this.killChild);
    this.child.stdout.on('data', (data) => {
      if (data.indexOf('percent') > -1) {
        // console.log(data.toString());
      } else {
        this.rawData += data;
      }
    });

    this.child.on('error', (err) => {
      this.killChild();
      if (err.code === 'ENOENT') {
        this.emit('error', 'NMAP not found at command location: ' + nmap.nmapLocation);
      } else {
        this.emit('error', err.Error);
      }
    });

    this.child.stderr.on('data', (err) => {
      this.error = err.toString();
    });

    this.child.on('close', () => {
      process.removeListener('SIGINT', this.killChild);
      process.removeListener('uncaughtException', this.killChild);
      process.removeListener('exit', this.killChild);

      if (this.error) {
        this.emit('error', this.error);
      } else if (this.cancelled === true) {
        this.emit('error', 'Over scan timeout ' + this.scanTimeout);
      } else {
        this.rawDataHandler(this.rawData);
      }
    });
  }

  startScan() {
    this.child.stdin.end();
  }

  cancelScan() {
    this.killChild();
    this.emit('error', 'Scan cancelled');
  }

  scanComplete(results) {
    this.scanResults = results;
    this.stopTimer();
    this.emit('complete', this.scanResults);
  }

  rawDataHandler(data) {
    let results;
    // turn NMAP's xml output into a json object
    xml2js.parseString(data, (err, result) => {
      if (err) {
        this.emit('error', 'Error converting XML to JSON in xml2js: ' + err);
      } else {
        this.rawJSON = result;
        results = convertRawJsonToScanResults(this.rawJSON, (err) => {
          this.emit('error', 'Error converting raw json to cleans can results: ' + err + ': ' + this.rawJSON);
        });
        this.scanComplete(results);
      }
    });
  }
}


class QuickScan extends NmapScan {
  constructor(range, {sudo, sudoArgs} = {}) {
    super(range, '-sP', {sudo, sudoArgs});
  }
}
class OsAndPortScan extends NmapScan {
  constructor(range, sudoArgs = []) {
    super(range, '-O', { sudo: 'sudo', sudoArgs });
  }
}


class QueuedScan extends EventEmitter {
  constructor(scanClass, range, args, action = () => {}) {
    super();
    this.scanResults = [];
    this.scanTime = 0;
    this.currentScan;
    this.runActionOnError = false;
    this.saveErrorsToResults = false;
    this.singleScanTimeout = 0;
    this.saveNotFoundToResults = false;

    this._queue = new Queue((host) => {
      if (args !== null) {
        this.currentScan = new scanClass(host, args);
      } else {
        this.currentScan = new scanClass(host);
      }
      if (this.singleScanTimeout !== 0) {
        this.currentScan.scanTimeout = this.singleScanTimeout;
      }

      this.currentScan.on('complete', (data) => {
        this.scanTime += this.currentScan.scanTime;
        if (data[0]) {
          data[0].scanTime = this.currentScan.scanTime;
          this.scanResults = this.scanResults.concat(data);
        } else if (this.saveNotFoundToResults) {
          data[0] = {
            error: 'Host not found',
            scanTime: this.currentScan.scanTime,
          };
          this.scanResults = this.scanResults.concat(data);
        }
        action(data);
        this._queue.done();
      });

      this.currentScan.on('error', (err) => {
        this.scanTime += this.currentScan.scanTime;

        const data = {
          error: err,
          scanTime: this.currentScan.scanTime,
        };


        if (this.saveErrorsToResults) {
          this.scanResults = this.scanResults.concat(data);
        }
        if (this.runActionOnError) {
          action(data);
        }

        this._queue.done();
      });

      this.currentScan.startScan();
    });

    this._queue.add(this.rangeFormatter(range));

    this._queue.on('complete', () => {
      this.emit('complete', this.scanResults);
    });
  }

  rangeFormatter(range) {
    let outputRange = [];
    if (!Array.isArray(range)) {
      range = range.split(' ');
    }

    for (let i = 0; i < range.length; i++) {
      const input = range[i];
      let temprange = range[i];
      if (countCharacterOccurence(input, '.') === 3 &&
                input.match(new RegExp('-', 'g')) !== null &&
                !input.match(/^[a-zA-Z]+$/) &&
                input.match(new RegExp('-', 'g')).length === 1
      ) {
        const firstIP = input.slice(0, input.indexOf('-'));
        let network;
        const lastNumber = input.slice(input.indexOf('-') + 1);
        let firstNumber;
        const newRange = [];
        for (let j = firstIP.length - 1; j > -1; j--) {
          if (firstIP.charAt(j) === '.') {
            firstNumber = firstIP.slice(j + 1);
            network = firstIP.slice(0, j + 1);
            break;
          }
        }
        for (let iter = firstNumber; iter <= lastNumber; iter++) {
          newRange.push(network + iter);
        }
        // replace the range/host string with array
        temprange = newRange;
      }
      outputRange = outputRange.concat(temprange);
    }

    function countCharacterOccurence(input, character) {
      let num = 0;
      for (let k = 0; k < input.length; k++) {
        if (input.charAt(k) === character) {
          num++;
        }
      }
      return num;
    }
    return outputRange;
  }

  startRunScan(index = 0) {
    this.scanResults = [];
    this._queue.run(0);
  }

  startShiftScan() {
    this.scanResults = [];
    this._queue.shiftRun();
  }

  pause() {
    this._queue.pause();
  }

  resume() {
    this._queue.resume();
  }

  next(iterations = 1) {
    return this._queue.next(iterations);
  }

  shift(iterations = 1) {
    return this._queue.shift(iterations);
  }

  results() {
    return this.scanResults;
  }

  shiftResults() {
    this._queue.shiftResults();
    return this.scanResults.shift();
  }

  index() {
    return this._queue.index();
  }

  queue(newQueue) {
    if (Array.isArray(newQueue)) {
      return this._queue.queue(newQueue);
    } else {
      return this._queue.queue();
    }
  }

  percentComplete() {
    return Math.round(((this._queue.index() + 1) / this._queue.queue().length) * 100);
  }
}

class QueuedNmapScan extends QueuedScan {
  constructor(range, additionalArguments, actionFunction = () => {}) {
    super(NmapScan, range, additionalArguments, actionFunction);
  }
}

class QueuedQuickScan extends QueuedScan {
  constructor(range, actionFunction = () => {}) {
    super(QuickScan, range, null, actionFunction);
  }
}

class QueuedOsAndPortScan extends QueuedScan {
  constructor(range, actionFunction = () => {}) {
    super(OsAndPortScan, range, null, actionFunction);
  }
}

const nmap = {
  nmapLocation: 'nmap',
  NmapScan,
  QuickScan,
  OsAndPortScan,
  QueuedScan,
  QueuedNmapScan,
  QueuedQuickScan,
  QueuedOsAndPortScan,
};

module.exports = nmap;
