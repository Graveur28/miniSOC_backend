import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';
import { AlerteService } from './alerte.service';
import { CreateAlerteDto } from './dto/create-alerte.dto';
import { UpdateAlerteDto } from './dto/update-alerte.dto';

@Controller('alerte')
export class AlerteController {
  constructor(private readonly alerteService: AlerteService) {}

  @Post()
  create(@Body() createAlerteDto: CreateAlerteDto) {
    return this.alerteService.create(createAlerteDto);
  }

  @Get()
  findAll() {
    return this.alerteService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.alerteService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateAlerteDto: UpdateAlerteDto) {
    return this.alerteService.update(+id, updateAlerteDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.alerteService.remove(+id);
  }
}
