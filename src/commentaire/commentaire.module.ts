import { Module } from '@nestjs/common';
import { CommentaireService } from './commentaire.service';
import { CommentaireController } from './commentaire.controller';

@Module({
  controllers: [CommentaireController],
  providers: [CommentaireService],
})
export class CommentaireModule {}
