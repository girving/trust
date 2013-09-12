// Web of trust visualization

'use strict'
var keyserver = 'http://sks.keyservers.net:11371'
var root = strip('2B90 56C0 1793 3F4B 12CA  2E3D F87A 09CB 27AB 7E55')
console.log('root',root)

function strip(s) {
  return s.replace(/\s+/g,'')
}

function show_id(id) {
  return util.hexstrdump(id)
}

// A web of trust graph
function Graph() {
  // Nodes in order of discovery.  Fields:
  //   index - index into nodes array
  //   id - 8 byte key id
  //   key - public key if we have it
  function Node (index,id) {
    this.index = index
    this.id = id
    this.toString = function () { return show_id(this.id) }
    // Key undefined at first
  }
  this.nodes = []

  // key id -> node
  this.id_to_node = {}

  // a -> b -> link if b signs a.  The link has fields
  //   id - id of the key signed (a)
  //   issuer - id of the signer (b) 
  //   code - one of the following, taken from http://openpgpjs.org/openpgpjs/doc/openpgp_packet_userid.html
  //     0 - bad
  //     1 - expired
  //     2 - issuer not available 
  //     3 - revoked
  //     4 - valid
  //     5 - signature by key owner expired
  //     6 - signature by key owner revoked
  function Sig (node,issuer,code,link) {
    this.node = node
    this.issuer = issuer
    this.code = code
    this.link = link
    this.toString = function () { return show_id(this.node.id)+'-'+show_id(this.issuer.id)+'-'+this.code }
  }
  function Link (source,target) {
    this.source = source
    this.target = target
  }
  this.links = [] // Ordered list of link objects
  this.all_sigs = [] // Ordered list of all sig objects
  this.sigs = {} // a -> b -> link if b signs a
  this.inv_sigs = {} // a -> b -> true if a in sigs[b]

  // Should be called after any changes
  this.onchange = function () {}

  // Add a new node, or return the existing node if it doesn't exist
  this.add_node = function (id) {
    if (id in this.id_to_node)
      return this.id_to_node[id]
    if (id.length != 8)
      throw 'bad length '+id.length
    var i = this.nodes.length
    var node = new Node(i,id)
    this.nodes[i] = this.id_to_node[id] = node
    this.sigs[id] = {}
    this.inv_sigs[id] = {}
    return node
  }

  // b signs a with given code
  this.add_edge = function (a,b,code) {
    var an = this.add_node(a)
    var bn = this.add_node(b)
    if (!(b in this.sigs[a])) {
      var link = a in this.sigs[b] ? this.sigs[b][a].link
                                   : new Link(an,bn)
      var sig = new Sig(an,bn,code,link)
      this.all_sigs.push(sig)
      if (link.source === an)
        this.links.push(link)
      this.sigs[a][b] = sig
      this.inv_sigs[b][a] = true
    } else
      this.sigs[a][b].code = code
  }

  this.short_name = function (id) {
    var node = this.id_to_node[id]
    return 'key' in node ? node.key.userIds[0].text.split(' ')[0]
                         : show_id(id)
  }

  this.long_name = function (id) {
    var node = this.id_to_node[id]
    return 'key' in node ? node.key.userIds[0].text
                         : show_id(id)
  }

  this.dump = function () {
    for (var i=0;i<this.nodes.length;i++) {
      var a = this.nodes[i]
      if ('key' in a) {
        console.log(this.short_name(a.id))
        for (var b in this.sigs[a.id])
          console.log('  '+this.short_name(b)+' : '+this.sigs[a.id][b].code)
      }
    }
  }
}

// Asynchronous request the given key id, and call receive_key one we have it
var requested = {}
function request_key(graph,id) {
  if (id in requested)
    return
  requested[id] = true
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

// Process a newly arrived key
function receive_key(graph,key) {
  var id = key.getKeyId()
  graph.add_node(id,key).key = key
  console.log('received key',show_id(id),key.userIds[0].text)
  for (var a in graph.inv_sigs[id])
    update_key(graph,a)
  update_key(graph,id)
  graph.onchange()
}

// Check all signatures for the given key id.  This is called once
// when the key first arrives, and again whenever a signatory's key arrives.
function update_key(graph,id) {
  var key = graph.id_to_node[id].key
  var user = key.userIds[0]
  var codes = user.verifyCertificationSignatures(key)
  for (var i=0;i<codes.length;i++) {
    var sig = user.certificationSignatures[i];
    var issuer = sig.getIssuer()
    if (id != issuer) {
      graph.add_edge(id,issuer,codes[i])
      if (codes[i]==2)
        request_key(graph,issuer)
    }
  }
}

// Toplevel
window.onload = function () {
  openpgp.init()
  var graph = new Graph()
  var width = 640
  var height = 480
  var radius = 10
  var bend = .07
  var svg = d3.select('body').append('svg')
    .attr('width',width)
    .attr('height',height)
  svg.append('defs').selectAll('marker')
      .data(['valid','invalid','pending'])
    .enter().append('marker')
      .attr('id',String)
      .attr('orient','auto')
      .attr('markerWidth',10)
      .attr('markerHeight',10)
      .attr('refX',2)
      .attr('refY',2)
      .append('polygon')
        .attr('points','4,2 0,4 0,0')
  var force = d3.layout.force()
    .linkDistance(100)
    .size([width,height])

  var sig_colors = {valid:'green',invalid:'red',pending:'orange'}
  function sig_status (sig) {
    if (sig.code==4) return 'valid'
    if (sig.code==2) return 'pending'
    return 'invalid'
  }

  function sig_path (sig) {
    var x0 = sig.issuer.x, 
        y0 = sig.issuer.y,
        x4 = sig.node.x,
        y4 = sig.node.y
    if (sig.node.id in graph.sigs[sig.issuer.id]) { // Flipped edge exists, use an arc
      // We subdivide once so that the midpoint exists for arrow purposes
      var xc = .5*(x0+x4)+bend*(y4-y0),
          yc = .5*(y0+y4)-bend*(x4-x0),
          x1 = .5*(x0+xc),
          y1 = .5*(y0+yc),
          x3 = .5*(x4+xc),
          y3 = .5*(y4+yc),
          x2 = .5*(x1+x3),
          y2 = .5*(y1+y3)
      return 'M'+x0+','+y0
           +' Q'+x1+','+y1
           + ' '+x2+','+y2
           +' T'+x4+','+y4 
    }
    var x2 = .5*(x0+x4),
        y2 = .5*(y0+y4)
    return 'M'+x0+','+y0
         +' L'+x2+','+y2
         + ' '+x4+','+y4
  }

  graph.onchange = function () {
    force.nodes(graph.nodes)
    force.links(graph.links)
    force.start()

    var sig = svg.selectAll('.sig')
      .data(graph.all_sigs)
    sig.enter().insert('path','.node')
      .attr('class','sig')
    sig.style('stroke', function (s) { return sig_colors[sig_status(s)] })
      .attr('marker-mid', function (s) { return 'url(#'+sig_status(s)+')' })

    var node = svg.selectAll('.node')
      .data(graph.nodes)

    node.enter().append('circle')
      .attr('class','node')
      .attr('r',radius)
      .call(force.drag)
      .append('title')
    
    node.selectAll('title')
      .text(function (d) { return graph.long_name(d.id) })

    force.on('tick', function () {
      sig.attr('d',sig_path)
      node.attr('cx', function (d) { return d.x })
          .attr('cy', function (d) { return d.y })
    })
  }

  // Request the first key!
  var rid = util.hex2bin(root)
  if (rid.length >= 8) {
    graph.add_node(rid.substr(rid.length-8))
    graph.onchange()
  }
  request_key(graph,rid)
}
