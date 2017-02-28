# User handler for MSCP services

Requirements:
- A running mscp-metadata service

Include it as a handler:
```
let mscp = new MSCP({"": require("./handler.js"), "user": require("mscp-user")})
```

In handlers needing to check for username:

```
const User = require("mscp-user")
async init(){
  ....
  this.username = User.getUsernameFromHandlerRequest(this)
  ...
}
async validateAccess(functionName){
  return this.username ? true : false
}
```

Don't forget to add the function login (and optionally createUser and isLoggedIn) to your service in the namespace "user".
