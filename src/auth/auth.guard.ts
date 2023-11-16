import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { Reflector } from '@nestjs/core';
import { IS_REFRESH_KEY } from 'src/refresh-decorator';
import { JwtService } from 'src/nestjwtcustom/jwt.service';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';
import { PayLoad } from './types/Payload.type';
import { ConfigService } from '@nestjs/config';
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private refector: Reflector,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private prisma: PrismaService,
    private configService: ConfigService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    //Is route to refresh token service
    const isRefresh = this.refector.getAllAndOverride<boolean>(IS_REFRESH_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    //If this route depends on the refresh token service => get the refresh token secret
    //else AT token secret
    const secret = isRefresh
      ? this.configService.get('secretRT')
      : this.configService.get('secretAT');

    //Force request type to HTTP
    const request = context.switchToHttp().getRequest();

    //Get the token was sent
    const token = this.extractTokenFromHeader(request);
    if (!token) {
      throw new UnauthorizedException();
    }

    //Check the jwt token is valid
    let payload;
    try {
      payload = await this.jwtService.verifyAsync<PayLoad>(token, {
        secret: secret,
      });
      request.user = payload;
    } catch {
      throw new UnauthorizedException();
    }

    //check if email was existed
    const user = await this.prisma.user.findUnique({
      where: {
        email: payload.email,
      },
    });

    if (!user) {
      throw new UnauthorizedException();
    }

    //check is the token signature still valid: check if it matches with the stored in the redis
    const signature = token.split('.')[2];
    const storedToken = <
      { signatureAccessTokenHash: string; signatureRefreshTokenHash: string }
    >await this.cacheManager.get(`${payload.userId}`);

    //if the token does not exist => throw an error
    if (!storedToken) {
      throw new UnauthorizedException();
    }

    let isEqual;
    if (isRefresh) {
      //refresh token
      isEqual = await bcrypt.compare(
        signature,
        storedToken.signatureRefreshTokenHash,
      );
    } else {
      //access token
      isEqual = await bcrypt.compare(
        signature,
        storedToken.signatureAccessTokenHash,
      );
    }

    if (!isEqual) {
      throw new UnauthorizedException();
    }

    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
