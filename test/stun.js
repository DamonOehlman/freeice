const test = require('tape');
const freeice = require('..');

// Live probes live in tools/ice-check: they need the network, and a server
// dying says nothing about this package's code. What is tested here is the
// shape `freeice()` promises to a consumer.

test('by default 2 stun servers are returned', function(t) {
  var iceServers;

  t.plan(2);
  iceServers = freeice();
  t.ok(Array.isArray(iceServers), 'we have a server array');
  t.equal(iceServers.length, 2, 'we have 2 servers');
});
