var freeice = require('./');

// return 2 stun servers (default behaviour)
console.log(freeice());

// choose 4 stun servers
console.log(freeice({ stun: 4 }));

// choose 1 stun server and 1 turn server
// will work once if we end up with free turn servers
console.log(freeice({ stun: 1, turn: 1 }));