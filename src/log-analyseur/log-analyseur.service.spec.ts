import { Test, TestingModule } from '@nestjs/testing';
import { LogAnalyseurService } from './log-analyseur.service';

describe('LogAnalyseurService', () => {
  let service: LogAnalyseurService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [LogAnalyseurService],
    }).compile();

    service = module.get<LogAnalyseurService>(LogAnalyseurService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
