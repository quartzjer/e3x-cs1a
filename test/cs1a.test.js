var expect = require('chai').expect;
var cs1a = require("../node.js");

describe('cs1a', function(){

  // fixtures
  var pair = {key:new Buffer('03be277f53630a084de2f39c7ff9de56c38bb9d10c','hex'), secret:new Buffer('792fd655c8e03ae16e0e49c3f0265d04689cbea3','hex')};
  var rpair = {key:new Buffer('0365694904381c00dfb7c01bb16b0852ea584a1b0b','hex'), secret:new Buffer('031b502b0743b80c1575f4b459792b5d76ad636d','hex')};
  var mbody = new Buffer('53fa3dbd02099aa5fc8614ef40c8b5ead8070f375e650ae2becb4849fdca4e','hex');
  var cbody = new Buffer('3e7eaf57db5f407cfde1','hex');
  
  it('should export an object', function(){
    expect(cs1a).to.be.a('object');
  });

  it('should report id', function(){
    expect(cs1a.id).to.be.equal('1a');
  });

  it('should grow a pair', function(done){
    cs1a.generate(function(err, pair){
      expect(err).to.not.exist;
      expect(pair).to.be.a('object');
      expect(Buffer.isBuffer(pair.key)).to.be.equal(true);
      expect(pair.key.length).to.be.equal(21);
      expect(Buffer.isBuffer(pair.secret)).to.be.equal(true);
      expect(pair.secret.length).to.be.equal(20);
//      console.log("KEY",pair.key.toString('hex'),"SECRET",pair.secret.toString('hex'));
      done(err);
    });
  });

  it('should load a pair', function(){
    var local = new cs1a.Local(pair);
    expect(local).to.be.a('object');
    expect(local.decrypt).to.be.a('function');
  });

  it('should local decrypt', function(){
    var local = new cs1a.Local(pair);
    // created from remote encrypt
    var inner = local.decrypt(mbody);
    expect(Buffer.isBuffer(inner)).to.be.equal(true);
    expect(inner.length).to.be.equal(2);
    expect(inner.toString('hex')).to.be.equal('0000');
  });

  it('should load a remote', function(){
    var remote = new cs1a.Remote(rpair.key);
    expect(remote.verify).to.be.a('function');
    expect(remote.encrypt).to.be.a('function');
  });

  it('should remote encrypt', function(){
    var local = new cs1a.Local(rpair);
    var remote = new cs1a.Remote(pair.key);
    var message = remote.encrypt(local, new Buffer('0000','hex'));
    expect(Buffer.isBuffer(message)).to.be.equal(true);
    expect(message.length).to.be.equal(31);
//    console.log("MBODY",message.toString('hex'));
  });

  it('should remote verify', function(){
    var local = new cs1a.Local(rpair);
    var remote = new cs1a.Remote(pair.key);
    var bool = remote.verify(local, mbody);
    expect(bool).to.be.equal(true);
  });

  it('should dynamically encrypt, decrypt, and verify', function(){
    var local = new cs1a.Local(pair);
    var remote = new cs1a.Remote(rpair.key);
    var inner = new Buffer('4242','hex');
    var outer = remote.encrypt(local, inner);

    // now invert them to decrypt
    var local = new cs1a.Local(rpair);
    var remote = new cs1a.Remote(pair.key);
    expect(local.decrypt(outer).toString('hex')).to.be.equal(inner.toString('hex'));
    
    // verify sender
    expect(remote.verify(local,outer)).to.be.equal(true);
  });

  it('should load an ephemeral', function(){
    var remote = new cs1a.Remote(rpair.key);
    var ephemeral = new cs1a.Ephemeral(remote, mbody);
    expect(ephemeral.decrypt).to.be.a('function');
    expect(ephemeral.encrypt).to.be.a('function');
  });

  it('ephemeral encrypt', function(){
    var remote = new cs1a.Remote(rpair.key);
    var ephemeral = new cs1a.Ephemeral(remote, mbody);
    var channel = ephemeral.encrypt(new Buffer('0000','hex'));
    expect(Buffer.isBuffer(channel)).to.be.equal(true);
    expect(channel.length).to.be.equal(10);
    console.log("CBODY",channel.toString('hex'));
  });

  it('ephemeral decrypt', function(){
    var remote = new cs1a.Remote(rpair.key);
    var ephemeral = new cs1a.Ephemeral(remote, mbody);
    var channel = ephemeral.decrypt(cbody);
    expect(Buffer.isBuffer(channel)).to.be.equal(true);
    expect(channel.length).to.be.equal(2);
  });

});

/*
// dummy functions
cs1a.install({pdecode:function(){console.log("pdecode",arguments);return {}},pencode:function(){console.log("pencode",arguments);return new Buffer(0)}});

var a = {parts:{}};
var b = {parts:{}};
cs1a.genkey(a,function(){
  console.log("genkey",a);
  cs1a.genkey(b,function(){
    console.log("genkey",b);
    var id = {cs:{"1a":{}}};
    cs1a.loadkey(id.cs["1a"],a["1a"],a["1a_secret"]);
    var to = {};
    cs1a.loadkey(to,b["1a"]);
    console.log(id,to);
    var open = cs1a.openize(id,to,{});
    console.log("opened",open);
  });
});
*/