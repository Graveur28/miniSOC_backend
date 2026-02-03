import { Test, TestingModule } from '@nestjs/testing';
import { LogAnalyseurController } from './log-analyseur.controller';
import { LogAnalyseurService } from './log-analyseur.service';

describe('LogAnalyseurController', () => {
  let controller: LogAnalyseurController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [LogAnalyseurController],
      providers: [LogAnalyseurService],
    }).compile();

    controller = module.get<LogAnalyseurController>(LogAnalyseurController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
