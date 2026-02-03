import { Test, TestingModule } from '@nestjs/testing';
import { AlerteController } from './alerte.controller';
import { AlerteService } from './alerte.service';

describe('AlerteController', () => {
  let controller: AlerteController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AlerteController],
      providers: [AlerteService],
    }).compile();

    controller = module.get<AlerteController>(AlerteController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
