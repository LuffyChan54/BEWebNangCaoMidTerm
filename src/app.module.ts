import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { CacheModule, CacheStore } from '@nestjs/cache-manager';
import { redisStore } from 'cache-manager-redis-store';
import { RedisClientOptions } from 'redis';
import { PrismaModule } from './prisma/prisma.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from './nestjwtcustom/jwt.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    AuthModule,
    UsersModule,
    CacheModule.registerAsync<RedisClientOptions>({
      isGlobal: true,
      useFactory: async () => {
        const store = await redisStore({
          url: 'redis://default:3065oIEuyaX6aZrocH9cJOpm414aRBHp@redis-15850.c302.asia-northeast1-1.gce.cloud.redislabs.com:15850',
        });
        return {
          store: store as unknown as CacheStore,
        };
      },
    }),
    PrismaModule,
    JwtModule.registerAsync({
      global: true,
      useFactory: (configService: ConfigService) => {
        return {
          secretAT: configService.get('secretAT'),
          secretRF: configService.get('secretRT'),
          signATOption: {
            expiresIn: configService.get('expiresInAT'),
          },
          signRTOption: {
            expiresIn: configService.get('expiresInRT'),
          },
        };
      },
      inject: [ConfigService],
    }),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
