const MSCP = require("mscp");
const Handler = require("./handler.js");

(async () => {
  let mscp = new MSCP(Handler)
  await mscp.start();
})()
