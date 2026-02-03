import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';
import { LogAnalyseurService } from './log-analyseur.service';
import { CreateLogAnalyseurDto } from './dto/create-log-analyseur.dto';
import { UpdateLogAnalyseurDto } from './dto/update-log-analyseur.dto';

@Controller('log-analyseur')
export class LogAnalyseurController {
  constructor(private readonly logAnalyseurService: LogAnalyseurService) {}

  @Post()
  create(@Body() createLogAnalyseurDto: CreateLogAnalyseurDto) {
    return this.logAnalyseurService.create(createLogAnalyseurDto);
  }

  @Get()
  findAll() {
    return this.logAnalyseurService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.logAnalyseurService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateLogAnalyseurDto: UpdateLogAnalyseurDto) {
    return this.logAnalyseurService.update(+id, updateLogAnalyseurDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.logAnalyseurService.remove(+id);
  }
}
