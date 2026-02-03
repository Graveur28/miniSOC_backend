import { Test, TestingModule } from '@nestjs/testing';
import { AlerteService } from './alerte.service';

describe('AlerteService', () => {
  let service: AlerteService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AlerteService],
    }).compile();

    service = module.get<AlerteService>(AlerteService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
