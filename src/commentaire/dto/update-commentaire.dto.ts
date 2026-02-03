import { PartialType } from '@nestjs/mapped-types';
import { CreateCommentaireDto } from './create-commentaire.dto';

export class UpdateCommentaireDto extends PartialType(CreateCommentaireDto) {}
