import { Module } from '@nestjs/common';
import { LogAnalyseurService } from './log-analyseur.service';
import { LogAnalyseurController } from './log-analyseur.controller';

@Module({
  controllers: [LogAnalyseurController],
  providers: [LogAnalyseurService],
})
export class LogAnalyseurModule {}
