import { PartialType } from '@nestjs/mapped-types';
import { CreateLogAnalyseurDto } from './create-log-analyseur.dto';

export class UpdateLogAnalyseurDto extends PartialType(CreateLogAnalyseurDto) {}
