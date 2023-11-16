import { Injectable } from '@nestjs/common';
import { UserInfo } from './types/UserInfo.type';
import { PrismaService } from 'src/prisma/prisma.service';
import { UpdateDTO } from './types';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async findOne(req: any): Promise<UserInfo> {
    const userAuth = req.user;

    const user = await this.prisma.user.findUnique({
      where: {
        email: userAuth.email,
      },
    });

    const { password, ...userInfo } = user;
    return userInfo;
  }

  async updateOne(updateDTO: UpdateDTO, user: UserInfo): Promise<UserInfo> {
    const userUpdated = await this.prisma.user.update({
      where: {
        userId: user.userId,
      },
      data: {
        fullname: updateDTO.fullname,
        avatar: updateDTO.avatar,
        birthday: new Date(updateDTO.birthday),
        notes: updateDTO.notes,
      },
    });

    const { password, ...userInfo } = userUpdated;

    return userInfo;
  }
}
