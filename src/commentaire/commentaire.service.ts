import { Injectable } from '@nestjs/common';
import { CreateCommentaireDto } from './dto/create-commentaire.dto';
import { UpdateCommentaireDto } from './dto/update-commentaire.dto';

@Injectable()
export class CommentaireService {
  create(createCommentaireDto: CreateCommentaireDto) {
    return 'This action adds a new commentaire';
  }

  findAll() {
    return `This action returns all commentaire`;
  }

  findOne(id: number) {
    return `This action returns a #${id} commentaire`;
  }

  update(id: number, updateCommentaireDto: UpdateCommentaireDto) {
    return `This action updates a #${id} commentaire`;
  }

  remove(id: number) {
    return `This action removes a #${id} commentaire`;
  }
}
