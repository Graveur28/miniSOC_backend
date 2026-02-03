import { Module } from '@nestjs/common';
import { AlerteService } from './alerte.service';
import { AlerteController } from './alerte.controller';

@Module({
  controllers: [AlerteController],
  providers: [AlerteService],
})
export class AlerteModule {}
