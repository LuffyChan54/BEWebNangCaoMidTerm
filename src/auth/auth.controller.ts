import {
  Body,
  Req,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Refresh } from 'src/refresh-decorator';
import { AuthGuard } from './auth.guard';
import { Request } from 'express';
import { AuthDTO } from './dto';
import { SignInDTO } from './dto/signin.dto';
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @HttpCode(HttpStatus.OK)
  @Post('signin')
  signIn(@Body() signInDTO: SignInDTO) {
    return this.authService.signIn(signInDTO);
  }

  @HttpCode(HttpStatus.CREATED)
  @Post('signup')
  signUp(@Body() authDTO: AuthDTO) {
    return this.authService.signUp(authDTO);
  }

  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  @Post('signout')
  signOut(@Req() req: Request) {
    return this.authService.signOut(req);
  }

  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @Refresh()
  @Post('refresh')
  refresh(@Req() req: Request) {
    return this.authService.refresh(req);
  }
}
