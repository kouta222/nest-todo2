import { Injectable, ForbiddenException } from '@nestjs/common';
import {
  PrismaClientInitializationError,
  PrismaClientKnownRequestError,
} from '@prisma/client/runtime/library';
import { ConfigService } from '@nestjs/config';
import * as bcypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { AuthDto } from './dto/auth.dto';
import { Msg, Jwt } from './interfaces/auth.interface';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}
  // get mail and password
  async signUp(dto: AuthDto): Promise<Msg> {
    const hased = await bcypt.hash(dto.password, 12);
    // prismaのDBと繋がっている
    try {
      await this.prisma.user.create({
        data: {
          email: dto.email,
          hashedPassword: hased,
        },
      });
      return {
        message: 'ok',
      };
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('This email is already taken');
        }
      }
      throw error;
    }
  }
  async login(dto: AuthDto): Promise<Jwt> {}
  async generateJwt(userId: number, email: string) {
    // これは何？
    const payload = {
      sub: userId,
      email,
    };
    const secret = this.config.get('JWT_SECRET');
    const token = await this.jwt.signAsync(payload, {
      expiresIn: '5m',
      secret: secret,
    });
    return {
      accessToke: token,
    };
  }
}
