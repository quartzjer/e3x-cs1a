var expect = require('chai').expect;
var cs1a = require("../node.js");

describe('cs1a', function(){

  it('should export an object', function(){
    expect(cs1a).to.be.a('object');
  });

  it('should report id', function(){
    expect(cs1a.id).to.be.equal('1a');
  });

  it('should generate a keypair', function(done){
    cs1a.generate(function(err, pair){
      expect(pair).to.be.a('object');
      expect(Buffer.isBuffer(pair.key)).to.be.equal(true);
      expect(pair.key.length).to.be.equal(21);
      expect(Buffer.isBuffer(pair.secret)).to.be.equal(true);
      expect(pair.secret.length).to.be.equal(20);
      done(err);
    });
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