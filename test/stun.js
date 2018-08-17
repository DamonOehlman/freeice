const stun = require('stun');
const {
  STUN_BINDING_REQUEST,
  STUN_ALLOCATE_REQUEST,
  STUN_ATTR_MAPPED_ADDRESS,
  STUN_ATTR_XOR_MAPPED_ADDRESS,
  RESPONSE_S,
  MAPPED_ADDRESS
} = stun.constants;
const servers = require('../stun.json');
const test = require('tape');
const MAX_RESPONSE_TIME = 10000;
const freeice = require('..');

test('by default 2 stun servers are returned', function(t) {
  var iceServers;

  t.plan(2);
  iceServers = freeice();
  t.ok(Array.isArray(iceServers), 'we have a server array');
  t.equal(iceServers.length, 2, 'we have 2 servers');
});

servers.forEach(url => {
  test(`can connect to ${url}`, t => {
    const parts = url.split(':');
    const host = parts[0];
    const port = parts[1] ? parseInt(parts[1], 10) : 3478;
    const server = stun.createServer();

    const responseTimer = setTimeout(function() {
      server.removeAllListeners('bindingResponse');
      server.removeAllListeners('error');
      server.close();

      t.fail(`server did not respond within ${MAX_RESPONSE_TIME}ms`);
      t.end();
    }, MAX_RESPONSE_TIME);

    server.on('error', t.ifError.bind(t));
    server.once('bindingResponse', stunMsg => {
      const mapped = stunMsg.getAttribute(STUN_ATTR_MAPPED_ADDRESS)
        || stunMsg.getAttribute(STUN_ATTR_XOR_MAPPED_ADDRESS);
      clearTimeout(responseTimer);
      server.close();

      if (mapped) {
        t.equal(mapped.value.family, 'IPv4');
        t.notEqual(mapped.value.port, null);
        t.notEqual(mapped.value.address, null);
      } else {
        t.fail('No valid response found');
      }
    });

    const request = stun.createMessage(STUN_BINDING_REQUEST);
    console.log('attempting to connect to host: ' + host + ', port: ' + port);
    t.plan(3);
    server.send(request, port, host);
  });
});
