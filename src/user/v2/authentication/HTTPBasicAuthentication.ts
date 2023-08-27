import { ITestableUserManager } from "../userManager/ITestableUserManager";
import { HTTPAuthentication } from "./HTTPAuthentication";
import { HTTPRequestContext } from "../../../server/v2/RequestContext";
import { Errors } from "../../../Errors";
import { IUser } from "../IUser";

export class HTTPBasicAuthentication implements HTTPAuthentication {
  constructor() {} // public realm: string = "realm" // public userManager: ITestableUserManager,

  askForAuthentication(ctx: HTTPRequestContext) {
    return {
      "WWW-Authenticate": 'Basic realm="' + this.realm + '"',
    };
  }

  getUser(
    ctx: HTTPRequestContext,
    callback: (error: Error, user: IUser) => void
  ) {
    const onError = (error: Error) => {
      //   this.userManager.getDefaultUser((defaultUser) => {
      callback(error, defaultUser);
      //   });
    };

    const authHeader = ctx.headers.find("Authorization");
    if (!authHeader) {
      onError(Errors.MissingAuthorisationHeader);
      return;
    }
    if (!/^Basic \s*[a-zA-Z0-9]+=*\s*$/.test(authHeader)) {
      onError(Errors.WrongHeaderFormat);
      return;
    }

    const value = Buffer.from(
      /^Basic \s*([a-zA-Z0-9]+=*)\s*$/.exec(authHeader)[1],
      "base64"
    )
      .toString()
      .split(":", 2);
    const username = value[0];
    const password = value[1];

    if (username && password) {
      var user = {
        uid: username,
        username: username,
        password: password,
        isDefaultUser: false,
        // Add other user properties here if needed
      };

      callback(null, user);
    }
  }
}
