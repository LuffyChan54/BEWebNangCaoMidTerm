import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Put,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from 'src/auth/auth.guard';
import { UsersService } from './users.service';
import { UpdateDTO, UserInfo } from './types';
@Controller('users')
@UseGuards(AuthGuard)
export class UsersController {
  constructor(private usersService: UsersService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  findOne(@Req() req: any) {
    return this.usersService.findOne(req);
  }

  @Put()
  @HttpCode(HttpStatus.OK)
  updateOne(@Body() updateDTO: UpdateDTO, @Req() req: any) {
    return this.usersService.updateOne(updateDTO, req.user as UserInfo);
  }
}
