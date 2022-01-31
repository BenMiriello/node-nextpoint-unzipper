var jsBigInt = typeof BigInt === 'function';

var bigInt = jsBigInt ? null : require('big-integer');
var Stream = require('stream');

// Backwards compatibility for node versions < 8
if (!Stream.Writable || !Stream.Writable.prototype.destroy)
  Stream = require('readable-stream');

Decrypt.prototype.generateTable = function() {
  var poly = 0xEDB88320, c;
  this.table = [];
  for (var n = 0; n < 256; n++) {
    c = n;
    for (var k = 0; k < 8; k++)
      c = (c & 1) ? poly ^ (c >>> 1) :  c = c >>> 1;
    table[n] = c >>> 0;
  }
}

function crc(ch,crc) {
  if (ch.charCodeAt)
    ch = ch.charCodeAt(0);        

  if (jsBigInt) {
    return parseInt(BigInt((key >> 8) & 0xffffff) ^ BigInt(table[(key ^ ch) & 0xff]), 10);
  } else {
    return (bigInt(crc).shiftRight(8).and(0xffffff)).xor(table[bigInt(crc).xor(ch).and(0xff)]).value;
  }
}

function Decrypt() {
  this.key0 = 305419896;
  this.key1 = 591751049;
  this.key2 = 878082192;

  this.generateTable();
}

Decrypt.prototype.update = function(h) {
  if (jsBigInt) {
    this.key0 = crc(h, this.key0);
    this.key1 = BigInt(this.key0 & 255 & 4294967295) + this.key1;
    this.key1 = ((this.key1 * 134775813n) + 1n) & 4294967295n;
    this.key2 = crc(parseInt(this.key1 >> 24n, 10) & 255, this.key2);
  } else {
    this.key0 = crc(h,this.key0);
    this.key1 = bigInt(this.key0).and(255).and(4294967295).add(this.key1)
    this.key1 = bigInt(this.key1).multiply(134775813).add(1).and(4294967295).value;
    this.key2 = crc(bigInt(this.key1).shiftRight(24).and(255), this.key2);
  }
}

Decrypt.prototype.decryptByte = function(c) {
  if (jsBigInt) {
    const k = BigInt(this.key2 | 2);
    c ^= parseInt((k * (k ^ 1n) >> 8n) & 255n, 10);
  } else {
    var k = bigInt(this.key2).or(2);
    c = c ^ bigInt(k).multiply(bigInt(k^1)).shiftRight(8).and(255);
  }
  this.update(c);
  return c;
};

Decrypt.prototype.stream = function() {
  var stream = Stream.Transform(),
      self = this;

  stream._transform = function(d,e,cb) {
    for (var i = 0; i<d.length;i++) {
      d[i] = self.decryptByte(d[i]);
    }
    this.push(d);
    cb();
  };
  return stream;
};

module.exports = Decrypt;
