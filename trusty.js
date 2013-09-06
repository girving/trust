// Web of trust visualization

'use strict'
var keyserver = 'http:/localhost:11371'
var root = strip('2B90 56C0 1793 3F4B 12CA  2E3D F87A 09CB 27AB 7E55')
console.log('root',root)

function strip(s) {
  return s.replace(/\s+/g,'')
}

function show_id(id) {
  return util.hexstrdump(id)
}

function Graph() {
  // key fingerprint -> key
  this.keys = {}

  // a -> b -> code if b's signature of a is
  //   0 - bad
  //   1 - expired
  //   2 - issuer not available 
  //   3 - revoked
  //   4 - valid
  //   5 - signature by key owner expired
  //   6 - signature by key owner revoked
  // This list from http://openpgpjs.org/openpgpjs/doc/openpgp_packet_userid.html
  this.sigs = {}
  this.inv_sigs = {} // a -> b -> true if a in sigs[b]

  this.add_key = function (key) {
    var id = key.getKeyId()
    if (id.length != 8)
      throw 'bad length '+id.length
    this.keys[id] = key
    if (!(id in this.sigs))
      this.sigs[id] = {}
    return id
  }

  // b signs a with given code
  this.add_edge = function (a,b,code) {
    if (a.length != 8 || b.length != 8)
      throw 'bad lengths '+a.length+' '+b.length
    if (!(a in this.keys))
      throw 'unknown key '+a 
    this.sigs[a][b] = code
    if (!(b in this.inv_sigs))
      this.inv_sigs[b] = {}
    this.inv_sigs[b][a] = true
  }

  this.short_name = function (id) {
    if (id in this.keys)
      return this.keys[id].userIds[0].text.split(' ')[0]
    return show_id(id)
  }

  this.log = function () {
    for (var a in this.keys) {
      console.log(this.short_name(a))
      for (var b in this.sigs[a])
        console.log('  '+this.short_name(b)+' : '+this.sigs[a][b])
    }
  }
}

function request_key(graph,id) {
  var sid = show_id(id)
  var xh = new XMLHttpRequest()
  xh.onreadystatechange = function () {
    if (xh.readyState==4) {
      if (xh.status==200) {
        var keys = openpgp.read_publicKey(xh.responseText)
        // Ideally, importPublicKey would return a list of the public keys.  Hack around the fact that it doesn't.
        var old_len = openpgp.keyring.publicKeys.length
        openpgp.keyring.importPublicKey(xh.responseText)
        var new_len = openpgp.keyring.publicKeys.length
        if (old_len==new_len)
          throw 'key import failed for id '+sid
        for (var i = old_len; i < new_len; i++)
          receive_key(graph,openpgp.keyring.publicKeys[i].obj)
      } else {
        console.error('error '+xh.status+' for key '+sid)
      }
    }
  }
  xh.open('GET',keyserver+'/pks/lookup?op=get&search=0x'+sid,true)
  xh.send() 
}

function receive_key(graph,key) {
  var id = graph.add_key(key)
  console.log('received key',show_id(id),key.userIds[0].text,key)
  for (var a in graph.inv_sigs[id])
    update_key(graph,a)
  update_key(graph,id)
}

function update_key(graph,id) {
  var key = graph.keys[id]
  var user = key.userIds[0]
  console.log('updating key',show_id(id),user.text,key)
  var codes = user.verifyCertificationSignatures(key)
  for (var i=0;i<codes.length;i++) {
    var sig = user.certificationSignatures[i];
    var issuer = sig.getIssuer()
    if (id != issuer) {
      console.log('signature',show_id(id),show_id(issuer),codes[i])
      graph.add_edge(id,issuer,codes[i])
      if (codes[i]==2)
        request_key(graph,issuer)
    }
  }
  graph.log()
}

function main() {
  openpgp.init()
  var graph = new Graph()
  request_key(graph,util.hex2bin(root))
}

window.onload = function () {
  main()
}
