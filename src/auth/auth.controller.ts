import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  Res,
  Req,
  Get,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { Csrf, Msg } from './interfaces/auth.interface';

// ロジックとルーティングを完全に分ける。
@Controller('auth')
export class AuthController {
  constructor(private readonly authSevice: AuthService) {}
  @Post('signup')
  //   @Bodyをつけることにより、JWTのbodyを取得できる。
  signUp(@Body() dto: AuthDto): Promise<Msg> {
    return this.authSevice.signUp(dto);
  }
}
