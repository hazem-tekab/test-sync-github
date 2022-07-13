import { Injectable } from "@nestjs/common";
import { PrismaService } from "nestjs-prisma";
// @ts-ignore
import { RequestContext } from "nestjs-request-context";

@Injectable()
export class DbService extends PrismaService {
  prismaClientsLocal = new PrismaService();
  constructor() {
    super();
    this.$use(async (params: any, next: any) => {
      let currentSession = this.getCurrentUser();
      if (params.runInTransaction) return next(params);
      const modelName: any =
        params.model.charAt(0).toLowerCase() + params.model.slice(1);
      const [, results] = await this.prismaClientsLocal.$transaction([
        this.prismaClientsLocal.$queryRawUnsafe(
          `set "request.jwt.claims" to '{ "sub": \"${currentSession.id}\"}';`
        ),
        // @ts-ignore
        this.prismaClientsLocal[modelName][params.action](params.args),
      ]);
      console.info("results", params.action, params.model, results);
      return results;
    });
  }

  getCurrentUser() {
    const session: any = RequestContext.currentContext.req;
    console.log("session", session);
    return session.user;
  }
}
