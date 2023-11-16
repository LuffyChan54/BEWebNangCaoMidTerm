import {
  BadRequestException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from 'src/nestjwtcustom/jwt.service';
import { hashRound } from './constants';
import * as bcrypt from 'bcrypt';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';
import { AuthDTO } from './dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { SignInDTO } from './dto/signin.dto';
import { ConfigService } from '@nestjs/config';
@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private prisma: PrismaService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private configService: ConfigService,
  ) {}

  async hashToken(token: string): Promise<string> {
    return await bcrypt.hash(token, hashRound);
  }

  async compareToken(token: string, hash: string): Promise<boolean> {
    return await bcrypt.compare(token, hash);
  }

  async signIn(authDTO: SignInDTO): Promise<any> {
    //find user by email
    const user = await this.prisma.user.findUnique({
      where: { email: authDTO.email },
    });

    if (!user) {
      throw new UnauthorizedException();
    }

    //get User info:
    const { password, createdAt, updatedAt, ...userInfo } = user;

    //check if user's password is correct
    const isCorrectPassword = await this.compareToken(
      authDTO.password,
      user.password,
    );
    if (!isCorrectPassword) {
      throw new UnauthorizedException();
    }

    //create the payload
    const payload = {
      userId: user.userId,
      email: user.email,
      fullname: user.fullname,
      role: user.role,
    };

    //get JWT access and refesh token
    const { accessToken, refreshToken } =
      await this.jwtService.signAsync(payload);

    //hash the signature of access token and refresh token to store in redis
    const signatureAccessTokenHash = await this.hashToken(
      accessToken.split('.')[2],
    );
    const signatureRefreshTokenHash = await this.hashToken(
      refreshToken.split('.')[2],
    );

    //store/override the stored hash token in redis
    const id: string = user.userId + '';
    await this.cacheManager.set(
      id,
      {
        signatureAccessTokenHash,
        signatureRefreshTokenHash,
      },
      this.configService.get('ttlrefresh'),
    );

    //return the access token and user info
    return {
      userInfo,
      token: { accessToken, refreshToken },
    };
  }

  async signUp(authDTO: AuthDTO): Promise<any> {
    //find user
    const tempUser = await this.prisma.user.findUnique({
      where: {
        email: authDTO.email,
      },
    });

    if (tempUser) {
      throw new BadRequestException('Email has been used');
    }

    //hash password
    const hashPassword = await this.hashToken(authDTO.password);

    //save new user into database
    const user = await this.prisma.user.create({
      data: {
        email: authDTO.email,
        fullname: authDTO.fullname,
        password: hashPassword,
      },
    });

    //get User info:
    const {
      password,
      createdAt,
      updatedAt,
      avatar,
      birthday,
      notes,
      ...userInfo
    } = user;

    return {
      userInfo,
    };
  }

  async signOut(req: any) {
    //get user
    let user = req.user;

    const id = user.userId;

    await this.cacheManager.del(id);

    // return 'singout';
  }

  async refresh(req: any): Promise<any> {
    //get user
    let user = req.user;

    //get the payload
    const payload = {
      userId: user.userId,
      fullname: user.fullname,
      email: user.email,
      role: user.role,
    };

    //else create new access token and refresh token
    const { accessToken, refreshToken } =
      await this.jwtService.signAsync(payload);

    //create new signature hash
    const signatureAccessTokenHash = await this.hashToken(
      accessToken.split('.')[2],
    );
    const signatureRefreshTokenHash = await this.hashToken(
      refreshToken.split('.')[2],
    );

    //write the new in redis
    const id: string = user.userId + '';
    await this.cacheManager.set(
      id,
      {
        signatureAccessTokenHash,
        signatureRefreshTokenHash,
      },
      this.configService.get('ttlrefresh'),
    );

    //return new token
    return {
      token: { accessToken, refreshToken },
    };
  }
}
