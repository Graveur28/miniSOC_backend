

export class CreateLogDto {
  @IsString()
  ipAddress: string;

  @IsOptional()
  @IsString()
  endpoint?: string;

  @IsOptional()
  @IsEnum(HttpMethod)
  method?: HttpMethod;

  @IsOptional()
  @IsInt()
  statusCode?: number;

  @IsOptional()
  @IsString()
  userAgent?: string;

  @IsOptional()
  @IsString()
  requestBody?: string;

  @IsOptional()
  @IsObject()
  requestHeaders?: any;

  @IsOptional()
  @IsString()
  responseBody?: string;
}
