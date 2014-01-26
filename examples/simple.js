var freeice = require('./');

// choose a single stun server
console.log(freeice());

// choose 2 stun servers
console.log(freeice({ stun: 2 }));

// choose 2 stun servers and 1 turn server
// will work once if we end up with free turn servers
console.log(freeice({ stun: 2, turn: 1 }));