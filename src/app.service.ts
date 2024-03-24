import { Injectable } from '@nestjs/common';

// @injectableをつけることにより、serviceのロジックを追加することができる
@Injectable()
export class AppService {
  getHello(): string {
    return 'Hello World!';
  }
}
