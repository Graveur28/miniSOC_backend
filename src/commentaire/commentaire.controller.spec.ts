import { Test, TestingModule } from '@nestjs/testing';
import { CommentaireController } from './commentaire.controller';
import { CommentaireService } from './commentaire.service';

describe('CommentaireController', () => {
  let controller: CommentaireController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [CommentaireController],
      providers: [CommentaireService],
    }).compile();

    controller = module.get<CommentaireController>(CommentaireController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
