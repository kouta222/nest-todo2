import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';

// エンドポイントを指定する
@Controller()
export class AppController {
  // constructorでAppServiceのインスタンス化を行う。AppContorllerに追加される
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }
}
