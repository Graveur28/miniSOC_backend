import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './user/user.module';
import { LogModule } from './log/log.module';
import { AlerteModule } from './alerte/alerte.module';
import { CommentaireModule } from './commentaire/commentaire.module';
import { AlerteActionModule } from './alerte-action/alerte-action.module';
import { ProxyModule } from './proxy/proxy.module';
import { IocModule } from './ioc/ioc.module';
import { DashboardModule } from './dashboard/dashboard.module';
import { AuthModule } from './auth/auth.module';
import { LogAnalyseurModule } from './log-analyseur/log-analyseur.module';

@Module({
  imports: [UserModule, LogModule, AlerteModule, CommentaireModule, AlerteActionModule, ProxyModule, IocModule, DashboardModule, AuthModule, LogAnalyseurModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
