"use strict"

const crypto = require('crypto')
const uuid = require("node-uuid")

class Handler{

  async init(){
    this.meta = this.mscp.meta
    this.userToken = this.request.data.usertoken || this.request.req.cookies["entityusertoken"]
    this.username = this.global.userToken2Username[this.userToken]
  }

  async initFirst(){
    let passwordSaltRows = await this.mscp.meta.find("tag:entity_password_salt")

    if(passwordSaltRows === undefined || passwordSaltRows == null){
      console.log("Error from mscp-user: Did you remember to add a metadata service? If not, add it and restart.")
      return;
    }

    if(passwordSaltRows.length == 0){
      this.global.passwordSalt = uuid.v4()
      await this.mscp.meta.addTag(this.global.passwordSalt, "entity_password_salt")
    } else {
      this.global.passwordSalt = passwordSaltRows[0]
    }

    let userRes = await this.mscp.meta.find("tag:entity_user", true)
    this.global.users = {}
    this.global.username2Id = {}
    for(let i = 0; i < userRes.length; i++){
      this.global.users[userRes[i].id] = userRes[i].properties
      this.global.username2Id[userRes[i].properties.username] = userRes[i].id
    }

    let userTokens = await this.mscp.meta.find("tag:entity_user_token", true)
    this.global.userToken2Username = {}
    for(let i = 0; i < userTokens.length; i++){
      let userId = userTokens[i].properties.userId
      this.global.userToken2Username[userTokens[i].id] = this.global.users[userId].username
    }
  }

  async validateAccess(functionName){
    if(Object.keys(this.global.users).length === 0 && this.global.users.constructor === Object) //We dont have any users yet
      return true
    else
      return this.username !== undefined || functionName == "user.login" || functionName == "user.isLoggedIn"
  }

  async createUser(username, password){
    if(this.global.username2Id[username] !== undefined)
      return false;

    let userId = crypto.createHash('sha256').update(username).digest('hex');
    let passwordHash = crypto.createHmac('sha256', this.global.passwordSalt).update(password).digest('hex');

    this.global.users[userId] = {username: username, passwordHash: passwordHash}
    this.global.username2Id[username] = userId

    await this.meta.addTag(userId, "entity_user")
    await this.meta.setProperties(userId, {username: username, passwordHash: passwordHash})
    return this.login(username, password)
  }

  async changePassword(oldPassword, newPassword){
    let userId = crypto.createHash('sha256').update(this.username).digest('hex');
    let passwordHashOld = crypto.createHmac('sha256', this.global.passwordSalt).update(oldPassword).digest('hex');
    let passwordHashNew = crypto.createHmac('sha256', this.global.passwordSalt).update(newPassword).digest('hex');
    if(this.global.users[userId] !== undefined && this.global.users[userId].passwordHash == passwordHashOld){
        await this.meta.setProperty(userId, "passwordHash", passwordHashNew)
        this.global.users[userId].passwordHash = passwordHashNew
        return true
    }
    return false
  }

  async login(username, password){
    let userId = crypto.createHash('sha256').update(username).digest('hex');
    let passwordHash = crypto.createHmac('sha256', this.global.passwordSalt).update(password).digest('hex');

    if(this.global.users[userId] !== undefined && this.global.users[userId].passwordHash == passwordHash){
      let userToken = uuid.v4()
      this.global.userToken2Username[userToken] = username
      await this.meta.addTag(userToken, "entity_user_token")
      await this.meta.setProperty(userToken, "userId", userId)
      this.request.res.cookie("entityusertoken", userToken, {expires: new Date(Date.now() + 1500000000), httpOnly: false });
      return userToken
    }
    return null
  }

  async logout(){
    this.request.res.clearCookie("entityusertoken");
    return true
  }

  async isLoggedIn(){
    return this.username !== undefined
  }

  static getUsernameFromHandlerRequest(handlerInstance){
    let userHandler = new Handler()
    userHandler.global = handlerInstance.global
    userHandler.request = handlerInstance.request
    userHandler.mscp = handlerInstance.mscp
    userHandler.init()
    return userHandler.username
  }
}

module.exports = Handler
