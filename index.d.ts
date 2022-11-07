interface stunServer {
  credential?: any,
  url: string,
  urls: Array<string>,
  username?: any
}
interface opts {
  stun: Array<string>,
  turn: Array<string>,
  stunCount: number,
  turnCount: number,
}



declare function freeice(opts?: opts): stunServer[];

export = freeice;
