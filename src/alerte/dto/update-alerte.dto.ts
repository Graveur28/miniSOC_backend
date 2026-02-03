import { PartialType } from '@nestjs/mapped-types';
import { CreateAlerteDto } from './create-alerte.dto';

export class UpdateAlerteDto extends PartialType(CreateAlerteDto) {}
