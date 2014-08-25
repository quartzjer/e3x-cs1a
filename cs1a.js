var crypto = require('crypto');

exports.id = '1a';

// env-specific crypto methods
exports.crypt = function(ecc,aes)
{
  crypto.ecc = ecc;
  crypto.aes = aes;
}

exports.generate = function(cb)
{
  try {
    var k = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp160r1);
  }catch(E){
    return cb(E);
  }
  cb(null, {key:k.PublicKey, secret:k.PrivateKey});
}

exports.Local = function(pair)
{
  var self = this;
  try{
    self.key = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp160r1, pair.key, true);
    self.secret = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp160r1, pair.secret);
  }catch(E){}

  // decrypt message body and return the inner
  self.decrypt = function(body){
    if(!Buffer.isBuffer(body)) return false;
    if(body.length < 4+21+4) return false;

    var seq = body.readUInt32BE(0);
    var keybuf = body.slice(4,4+21);
    var innerc = body.slice(4+21,body.length-4);
    // mac is handled during verify stage

    try{
      var ephemeral = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp160r1, keybuf, true);
      var secret = self.secret.deriveSharedSecret(ephemeral);
    }catch(E){
      return false;
    }

    var key = fold(1,crypto.createHash("sha256").update(secret).digest());
    var iv = new Buffer(16);
    iv.fill(0);
    iv.writeUInt32BE(seq,0);

    // aes-128 decipher the inner
    try{
      var inner = crypto.aes(false, key, iv, innerc);
    }catch(E){
      return false;
    }
    
    return inner;
  };
}

exports.Remote = function(key)
{
  var self = this;
  try{
    self.endpoint = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp160r1, key, true);
    self.ephemeral = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp160r1);
  }catch(E){}

  // verifies the hmac on an incoming message body
  self.verify = function(local, body){
    if(!Buffer.isBuffer(body)) return false;

    // derive shared secret from both identity keys
    var secret = local.secret.deriveSharedSecret(self.endpoint);

    // hmac key is the secret and seq bytes combined
    var mac = fold(3,crypto.createHmac("sha256", Buffer.concat([secret,body.slice(0,4)])).update(body.slice(4,body.length-4)).digest());
    if(mac.toString('hex') != body.slice(body.length-4).toString('hex')) return false;
    
    return true;
  };

  self.encrypt = function(local, inner){
    if(!Buffer.isBuffer(inner)) return false;

    // get the shared secret to create the iv+key for the open aes
    try{
      var secret = self.ephemeral.deriveSharedSecret(self.endpoint);
    }catch(E){
      return false;
    }
    var key = fold(1,crypto.createHash("sha256").update(secret).digest());
    var seq = Math.floor(Date.now()/1000);
    var iv = new Buffer(16);
    iv.fill(0);
    iv.writeUInt32BE(seq,0);

    // encrypt the inner
    try{
      var innerc = crypto.aes(true, key, iv, inner);
      var macsecret = local.secret.deriveSharedSecret(self.endpoint);
    }catch(E){
      return false;
    }

    // prepend the key and hmac it
    var macd = Buffer.concat([self.ephemeral.PublicKey,innerc]);
    // key is the secret and seq bytes combined
    var hmac = fold(3,crypto.createHmac("sha256", Buffer.concat([macsecret,iv.slice(0,4)])).update(macd).digest());

    // create final message body
    return Buffer.concat([iv.slice(0,4),macd,hmac]);
  };

}

exports.Ephemeral = function(remote, body)
{
  var self = this;
  
  self.seq = crypto.randomBytes(4).readUInt32LE(0); // start from random place

  try{
    // extract received ephemeral key
    var key = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp160r1, body.slice(4,4+21), true);

    // get shared secret to make channel keys
    var secret = remote.ephemeral.deriveSharedSecret(key);
    self.encKey = fold(1,crypto.createHash("sha256")
      .update(secret)
      .update(remote.ephemeral.PublicKey)
      .update(key.PublicKey)
      .digest());
    self.decKey = fold(1,crypto.createHash("sha256")
      .update(secret)
      .update(key.PublicKey)
      .update(remote.ephemeral.PublicKey)
      .digest());
  }catch(E){}

  self.decrypt = function(outer){
    // extract the three buffers
    var seq = outer.slice(0,4);
    var cbody = outer.slice(4,outer.length-4);
    var mac1 = outer.slice(outer.length-4);

    // validate the hmac
    var key = Buffer.concat([self.decKey,seq]);
    var mac2 = fold(3,crypto.createHmac("sha256", key).update(cbody).digest());
    if(mac1.toString('hex') != mac2.toString('hex')) return false;

    // decrypt body
    var ivz = new Buffer(12);
    ivz.fill(0);
    try{
      var body = crypto.aes(false,self.decKey,Buffer.concat([seq,ivz]),cbody);
    }catch(E){
      return false;
    }
    return body;
  };

  self.encrypt = function(inner){
    // now encrypt the packet
    var iv = new Buffer(16);
    iv.fill(0);
    iv.writeUInt32LE(self.seq++,0);

    var cbody = crypto.aes(true, self.encKey, iv, inner);

    // create the hmac
    var key = Buffer.concat([self.encKey,iv.slice(0,4)]);
    var mac = fold(3,crypto.createHmac("sha256", key).update(cbody).digest());

    // return final body
    return Buffer.concat([iv.slice(0,4),cbody,mac]);
  };
}


// simple xor buffer folder
function fold(count, buf)
{
  if(!count || buf.length % 2) return buf;
  var ret = buf.slice(0,buf.length/2);
  for(i = 0; i < ret.length; i++) ret[i] = ret[i] ^ buf[i+ret.length];
  return fold(count-1,ret);
}

exports.genkey = function(ret,cbDone,cbStep)
{
}

exports.loadkey = function(id, pub, priv)
{
  if(typeof pub == "string") pub = new Buffer(pub,"base64");
  if(!Buffer.isBuffer(pub) || pub.length != 40) return "invalid public key";
  id.key = pub;
  id.public = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp160r1, Buffer.concat([new Buffer("04","hex"),id.key]), true);
  if(!id.public) return "public key load failed";

  if(priv)
  {
    if(typeof priv == "string") priv = new Buffer(priv,"base64");
    if(!Buffer.isBuffer(priv) || priv.length != 20) return "invalid private key";
    id.private = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp160r1, priv);
    if(!id.private) return "private key load failed";
  }
  return false;
}

exports.openize = function(id, to, inner)
{
	if(!to.ecc) to.ecc = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp160r1);
  var eccpub = to.ecc.PublicKey.slice(1);

  // get the shared secret to create the iv+key for the open aes
  var secret = to.ecc.deriveSharedSecret(to.public);
  var key = fold(1,crypto.createHash("sha256").update(secret).digest());
  var iv = new Buffer("00000000000000000000000000000001","hex");

  // encrypt the inner
  var body = (!Buffer.isBuffer(inner)) ? self.pencode(inner,id.cs["1a"].key) : inner;
  var cbody = crypto.aes(true, key, iv, body);

  // prepend the line public key and hmac it  
  var secret = id.cs["1a"].private.deriveSharedSecret(to.public);
  var macd = Buffer.concat([eccpub,cbody]);
  var hmac = fold(3,crypto.createHmac("sha256", secret).update(macd).digest());

  // create final body
  var body = Buffer.concat([hmac,macd]);
  return self.pencode(0x1a, body);
},

exports.deopenize = function(id, open)
{
  var ret = {verify:false};
  if(!open.body) return ret;

  var mac1 = open.body.slice(0,4).toString("hex");
  var pub = open.body.slice(4,44);
  var cbody = open.body.slice(44);

  try{
    ret.linepub = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp160r1, Buffer.concat([new Buffer("04","hex"),pub]), true);      
  }catch(E){
    console.log("ecc err",E);
  }
  if(!ret.linepub) return ret;

  var secret = id.cs["1a"].private.deriveSharedSecret(ret.linepub);
  var key = fold(1,crypto.createHash("sha256").update(secret).digest());
  var iv = new Buffer("00000000000000000000000000000001","hex");

  // aes-128 decipher the inner
  var body = crypto.aes(false, key, iv, cbody);
  var inner = self.pdecode(body);
  if(!inner) return ret;
  ret.inner = inner;

  // verify+load inner key info
  var epub;
  if(!open.from)
  {
    epub = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp160r1, Buffer.concat([new Buffer("04","hex"),inner.body]), true);
    if(!epub) return ret;
    ret.key = inner.body;
  }else{
    epub = open.from.public;
  }

  // verify the hmac
  var secret = id.cs["1a"].private.deriveSharedSecret(epub);
  var mac2 = fold(3,crypto.createHmac("sha256", secret).update(open.body.slice(4)).digest()).toString("hex");
  if(mac2 != mac1) return ret;

  // all good, cache+return
  ret.verify = true;
  ret.js = inner.js;
  return ret;
},

// set up the line enc/dec keys
exports.openline = function(from, open)
{
  from.lineIV = crypto.randomBytes(4).readUInt32LE(0); // start from random place
  from.lineInB = new Buffer(from.lineIn, "hex");
  var ecdhe = from.ecc.deriveSharedSecret(open.linepub);
  from.encKey = fold(1,crypto.createHash("sha256")
    .update(ecdhe)
    .update(new Buffer(from.lineOut, "hex"))
    .update(from.lineInB)
    .digest());
  from.decKey = fold(1,crypto.createHash("sha256")
    .update(ecdhe)
    .update(from.lineInB)
    .update(new Buffer(from.lineOut, "hex"))
    .digest());
  return true;
},

exports.lineize = function(to, packet)
{
	// now encrypt the packet
  var iv = new Buffer(16);
  iv.fill(0);
  iv.writeUInt32LE(to.lineIV++,12);

  var cbody = crypto.aes(true, to.encKey, iv, self.pencode(packet.js,packet.body));

  // prepend the IV and hmac it
  var mac = fold(3,crypto.createHmac("sha256", to.encKey).update(Buffer.concat([iv.slice(12),cbody])).digest());

  // create final body
  var body = Buffer.concat([to.lineInB,mac,iv.slice(12),cbody]);

  return self.pencode(null, body);
},

exports.delineize = function(from, packet)
{
  if(!packet.body) return "no body";
  // remove lineid
  packet.body = packet.body.slice(16);
  
  // validate the hmac
  var mac1 = packet.body.slice(0,4).toString("hex");
  var mac2 = fold(3,crypto.createHmac("sha256", from.decKey).update(packet.body.slice(4)).digest()).toString("hex");
  if(mac1 != mac2) return "invalid hmac";

  // decrypt body
  var iv = packet.body.slice(4,8);
  var ivz = new Buffer(12);
  ivz.fill(0);
  var body = packet.body.slice(8);
  var deciphered = self.pdecode(crypto.aes(false,from.decKey,Buffer.concat([ivz,iv]),body));
	if(!deciphered) return "invalid decrypted packet";

  packet.js = deciphered.js;
  packet.body = deciphered.body;
  return false;
}