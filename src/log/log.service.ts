import { SecurityAnalysis } from 'src/log-analyseur/log-analyseur.service';
import { CreateLogDto } from './dto/create-log.dto';
import { UpdateLogDto } from './dto/update-log.dto';
import { Injectable, HttpException, HttpStatus, ConflictException, InternalServerErrorException, NotFoundException } from '@nestjs/common';
//import { LogFilterDto } from './dto/log-filter.dto';


@Injectable()
export class LogService {

//private readonly logger = new Logger(LogsService.name);

  constructor(private prisma: PrismaService) {}

  /**
   * Crée un nouveau log
   * TODO: OK
   */
  async createLog(data: CreateLogDto) {
    try {
      const log = await this.prisma.log.create({
        data: {
          ...data,
          tags: data.tags || [],
          metadata: data.metadata || {},
          analyzedAt: data.isSuspicious || data.isMalicious ? new Date() : null,
        },
      });

      // Si le log est suspect, lancer une analyse automatique
      if (data.isSuspicious || data.isMalicious) {
        this.analyzeLogAsync(log.id);
      }

      return log;
    } catch (error) {
      if (error.code === 'P2002') { throw new ConflictException('Log already exists');}
      throw new InternalServerErrorException('Failed to create log');
    }
  }

  /**
   * Récupère un log par ID
   * TODO: OK
   */
  async getLogById(id: string) {
    try {
      const log = await this.prisma.log.findUnique({
        where: { id },
        include: {
          alert: {
            select: {
              id: true,
              title: true,
              severity: true,
              status: true,
            },
          },
          ioc: {
            select: {
              id: true,
              type: true,
              value: true,
              severity: true,
            },
          },
          user: {
            select: {
              id: true,
              username: true,
              email: true,
              role: true,
            },
          },
        },
      });

      if (!log) {
        throw new NotFoundException(`le log avec l'id: ${id} est introuvable`);
      }
      return log;

    } catch (error) {
      if (error instanceof NotFoundException) {throw error;}
      throw new InternalServerErrorException('Echec du serveur a retrouver le log');
    }
  }

  /**
   * Recherche des logs avec filtres
   * TODO: OK
   */
  async searchLogs(filters: LogFiltersDto) {
    try {
      const where = this.buildWhereClause(filters);
      
      const [logs, total] = await Promise.all([
        this.prisma.log.findMany({
          where,
          orderBy: { [filters.sortBy || 'timestamp']: filters.sortOrder || 'desc' },
          skip: filters.skip || 0,
          take: Math.min(filters.limit || 100, 1000),
          include: {
            alert: {
              select: { id: true, title: true, severity: true },
            },
            ioc: {
              select: { id: true, type: true, severity: true },
            },
          },
        }),
        this.prisma.log.count({ where }),
      ]);

      return {
        data: logs,
        meta: {
          total,
          page: Math.floor((filters.skip || 0) / (filters.limit || 100)) + 1,
          totalPages: Math.ceil(total / (filters.limit || 100)),
          limit: filters.limit || 100,
        },
      };
    } catch (error) {
      throw new InternalServerErrorException('Failed to search logs');
    }
  }

  /**
   * Met à jour un log
   */
  // async update(id: string, updateLogDto: UpdateLogDto) {
  //   try {
  //     const log = await this.prisma.log.update({
  //       where: { id },
  //       data: updateLogDto,
  //     });

  //     this.logger.log(`Log updated: ${id}`);
  //     return log;

  //   } catch (error) {
  //     if (error.code === 'P2025') {
  //       throw new HttpException('Log not found', HttpStatus.NOT_FOUND);
  //     }
      
  //     this.logger.error(`Failed to update log ${id}: ${error.message}`);
  //     throw new HttpException(
  //       'Failed to update log',
  //       HttpStatus.INTERNAL_SERVER_ERROR,
  //     );
  //   }
  // }

  /**
   * Supprime un log
   */
  // async remove(id: string) {
  //   try {
  //     await this.prisma.log.delete({
  //       where: { id },
  //     });

  //     this.logger.log(`Log deleted: ${id}`);
  //     return { message: 'Log deleted successfully' };

  //   } catch (error) {
  //     if (error.code === 'P2025') {
  //       throw new HttpException('Log not found', HttpStatus.NOT_FOUND);
  //     }
      
  //     this.logger.error(`Failed to delete log ${id}: ${error.message}`);
  //     throw new HttpException(
  //       'Failed to delete log',
  //       HttpStatus.INTERNAL_SERVER_ERROR,
  //     );
  //   }
  // }

  /**
   * Récupère les statistiques des logs
   */
  async getLogStats(timeRange: '24h' | '7d' | '30d' = '24h') {
    try {
      const startDate = this.getStartDate(timeRange);
      const [
        totalLogs,
        bySeverity,
        byAttackType,
        byStatusCode,
        topIPs,
        recentActivity,
      ] = await Promise.all([
        // Total des logs
        this.prisma.log.count({
          where: { timestamp: { gte: startDate } },
        }),
        
        // Distribution par sévérité
        this.prisma.log.groupBy({
          by: ['severity'],
          where: { timestamp: { gte: startDate } },
          _count: { _all: true },
        }),
        
        // Distribution par type d'attaque
        this.prisma.log.groupBy({
          by: ['attackType'],
          where: { 
            timestamp: { gte: startDate },
            attackType: { not: null },
          },
          _count: { _all: true },
        }),
        
        // Distribution par code de statut
        this.prisma.log.groupBy({
          by: ['statusCode'],
          where: { 
            timestamp: { gte: startDate },
            statusCode: { not: null },
          },
          _count: { _all: true },
        }),
        
        // Top IPs
        this.prisma.log.groupBy({
          by: ['sourceIp'],
          where: { timestamp: { gte: startDate } },
          _count: { _all: true },
          orderBy: { _count: { _all: 'desc' } },
          take: 10,
        }),
        
        // Activité récente (par heure)
        this.prisma.$queryRaw`
          SELECT 
            DATE_TRUNC('hour', timestamp) as hour,
            COUNT(*) as count,
            SUM(CASE WHEN is_blocked THEN 1 ELSE 0 END) as blocked_count
          FROM logs
          WHERE timestamp >= ${startDate}
          GROUP BY DATE_TRUNC('hour', timestamp)
          ORDER BY hour DESC
          LIMIT 24
        `,
      ]);

      return {
        timeRange,
        totalLogs,
        severityDistribution: bySeverity.reduce((acc, item) => ({
          ...acc,
          [item.severity]: item._count._all,
        }), {}),
        attackTypeDistribution: byAttackType.reduce((acc, item) => ({
          ...acc,
          [item.attackType]: item._count._all,
        }), {}),
        statusCodeDistribution: byStatusCode.reduce((acc, item) => ({
          ...acc,
          [item.statusCode]: item._count._all,
        }), {}),
        topIPs: topIPs.map(ip => ({
          ip: ip.sourceIp,
          count: ip._count._all,
        })),
        recentActivity,
      };

    } catch (error) {
      this.logger.error(`Failed to get log statistics: ${error.message}`);
      throw new HttpException(
        'Failed to retrieve log statistics',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Recherche des logs par IP
   */
  async findByIP(ip: string, limit: number = 50) {
    try {
      const logs = await this.prisma.log.findMany({
        where: { sourceIp: ip },
        orderBy: { timestamp: 'desc' },
        take: limit,
        include: {
          alert: {
            select: { id: true, title: true, status: true },
          },
        },
      });

      if (logs.length === 0) {
        throw new HttpException('No logs found for this IP', HttpStatus.NOT_FOUND);
      }

      // Calculer les statistiques pour cette IP
      const stats = await this.prisma.log.groupBy({
        by: ['severity', 'attackType', 'isBlocked'],
        where: { sourceIp: ip },
        _count: { _all: true },
      });

      return {
        logs,
        stats: {
          totalRequests: logs.length,
          blockedRequests: logs.filter(log => log.isBlocked).length,
          severityBreakdown: stats.reduce((acc, item) => ({
            ...acc,
            [item.severity]: (acc[item.severity] || 0) + item._count._all,
          }), {}),
          attackTypes: stats
            .filter(item => item.attackType)
            .map(item => ({
              type: item.attackType,
              count: item._count._all,
            })),
        },
      };

    } catch (error) {
      if (error instanceof HttpException) throw error;
      
      this.logger.error(`Failed to find logs by IP ${ip}: ${error.message}`);
      throw new HttpException(
        'Failed to search logs',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Exporte les logs au format CSV
   */
  async exportLogs(filters?: LogFilterDto) {
    try {
      const where = this.buildWhereClause(filters);
      
      const logs = await this.prisma.log.findMany({
        where,
        orderBy: { timestamp: 'desc' },
        take: 10000, // Limite d'export
      });

      // Convertir en CSV
      const headers = [
        'ID', 'Timestamp', 'Source IP', 'Method', 'URL', 'Status Code',
        'Severity', 'Attack Type', 'Blocked', 'Response Time', 'Analyzed At',
      ];
      
      const rows = logs.map(log => [
        log.id,
        log.timestamp.toISOString(),
        log.sourceIp,
        log.httpMethod,
        log.url,
        log.statusCode,
        log.severity,
        log.attackType,
        log.isBlocked,
        log.responseTime,
        log.analyzedAt?.toISOString(),
      ]);

      const csvContent = [
        headers.join(','),
        ...rows.map(row => row.join(',')),
      ].join('\n');

      return {
        csv: csvContent,
        count: logs.length,
        exportedAt: new Date().toISOString(),
      };

    } catch (error) {
      this.logger.error(`Failed to export logs: ${error.message}`);
      throw new HttpException(
        'Failed to export logs',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Nettoie les logs anciens
   */
  async cleanupOldLogs(maxAgeDays: number = 30): Promise<{ deleted: number }> {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - maxAgeDays);
      
      // Compter avant suppression
      const count = await this.prisma.log.count({
        where: { timestamp: { lt: cutoffDate } },
      });
      
      // Supprimer en batch
      const batchSize = 1000;
      let deleted = 0;
      
      while (deleted < count) {
        const logsToDelete = await this.prisma.log.findMany({
          where: { timestamp: { lt: cutoffDate } },
          take: batchSize,
          select: { id: true },
        });
        
        if (logsToDelete.length === 0) break;
        
        await this.prisma.log.deleteMany({
          where: {
            id: { in: logsToDelete.map(log => log.id) },
          },
        });
        
        deleted += logsToDelete.length;
        this.logger.log(`Deleted ${logsToDelete.length} old logs...`);
        
        // Petite pause pour éviter de surcharger la base
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      
      this.logger.log(`Total old logs deleted: ${deleted}`);
      return { deleted };
      
    } catch (error) {
      this.logger.error(`Failed to cleanup old logs: ${error.message}`);
      throw new HttpException(
        'Failed to cleanup logs',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Construit la clause WHERE pour les filtres
   */
  private buildWhereClause(filters?: LogFilterDto): any {
    try {
      const where: any = {};
    
    if (filters?.startDate || filters?.endDate) {
      where.timestamp = {};
      if (filters.startDate) where.timestamp.gte = new Date(filters.startDate);
      if (filters.endDate) where.timestamp.lte = new Date(filters.endDate);
    }
    
    if (filters?.severity?.length) {
      where.severity = { in: filters.severity };
    }
    
    if (filters?.attackType?.length) {
      where.attackType = { in: filters.attackType };
    }
    
    if (filters?.ip) {
      where.sourceIp = { contains: filters.ip };
    }
    
    if (filters?.url) {
      where.url = { contains: filters.url };
    }
    
    if (filters?.method) {
      where.httpMethod = filters.method;
    }
    
    if (typeof filters?.isBlocked === 'boolean') {
      where.isBlocked = filters.isBlocked;
    }
    
    return where;
    } catch (error) {
      
    }
  }


/**
 * ##############################################################
 * ##############################################################
 */





  //=ANALYSE DES LOGS 

  /**
   * Analyse un log pour détecter des menaces
   */
  private async analyseLogAsync(idLog: string) {
    try {
      const log = await this.prisma.log.findUnique({
        where: { id: idLog },
      });

      if (!log || log.analyzedAt) return;

      const analysis = await this.performSecurityAnalysis(log);

      await this.prisma.log.update({
        where: { id: idLog },
        data: {
          analyzedAt: new Date(),
          severity: analysis.severity,
          attackType: analysis.attackType,
          isMalicious: analysis.isMalicious,
          isSuspicious: analysis.isSuspicious,
          confidence: analysis.confidence,
          analysisResult: analysis.details,
        },
      });

      // Si menace critique, créer une alerte
      if (analysis.isMalicious && analysis.severity === 'CRITIQUE') {
        await this.createAlertFromLog(log, analysis);
      }
    } catch (error) {
      console.error('Error analyzing log:', error);
    }
  }

  /**
   * Analyse de sécurité sur un log
   */
  private async performSecurityAnalysis(log: Log): Promise<SecurityAnalysis> {
    const analysis: SecurityAnalysis = {
      isMalicious: false,
      isSuspicious: false,
      severity: 'BAS',
      confidence: 0,
      attackType: null,
      details: {},
    };

    // 1. Vérification des patterns dans le payload
    if (log.requestBody) {
      const payloadAnalysis = this.analyzePayload(log.requestBody);
      if (payloadAnalysis.isMalicious) {
        analysis.isMalicious = true;
        analysis.severity = payloadAnalysis.severity;
        analysis.confidence = payloadAnalysis.confidence;
        analysis.attackType = payloadAnalysis.attackType;
        analysis.details.payload = payloadAnalysis;
      }
    }

    // 2. Vérification de l'IP
    if (log.ipAddress) {
      const ipAnalysis = await this.analyzeIP(log.ipAddress);
      if (ipAnalysis.isMalicious && !analysis.isMalicious) {
        analysis.isMalicious = true;
        analysis.severity = ipAnalysis.severity;
        analysis.confidence = ipAnalysis.confidence;
        analysis.attackType = ipAnalysis.attackType || 'MALICIOUS_IP';
        analysis.details.ip = ipAnalysis;
      }
    }

    // 3. Vérification du User-Agent
    if (log.userAgent) {
      const uaAnalysis = this.analyzeUserAgent(log.userAgent);
      if (uaAnalysis.isSuspicious) {
        analysis.isSuspicious = true;
        analysis.severity = Math.max(analysis.severity, uaAnalysis.severity);
        analysis.confidence = Math.max(analysis.confidence, uaAnalysis.confidence);
        analysis.details.userAgent = uaAnalysis;
      }
    }

    // 4. Vérification des codes d'erreur
    if (log.statusCode && log.statusCode >= 400) {
      const errorAnalysis = this.analyzeErrorCode(log);
      if (errorAnalysis.isSuspicious && !analysis.isMalicious) {
        analysis.isSuspicious = true;
        analysis.severity = Math.max(analysis.severity, errorAnalysis.severity);
        analysis.confidence = Math.max(analysis.confidence, errorAnalysis.confidence);
        analysis.details.error = errorAnalysis;
      }
    }

    // 5. Vérification du comportement
    const behaviorAnalysis = await this.analyzeBehavior(log);
    if (behaviorAnalysis.isSuspicious) {
      analysis.isSuspicious = true;
      analysis.severity = Math.max(analysis.severity, behaviorAnalysis.severity);
      analysis.confidence = Math.max(analysis.confidence, behaviorAnalysis.confidence);
      analysis.details.behavior = behaviorAnalysis;
    }

    return analysis;
  }

  //=MÉTHODES D'ANALYSE

  /**
   * Analyse le payload pour des patterns malveillants
   */
  private analyzePayload(payload: string): PayloadAnalysis {
    const patterns = [
      {
        pattern: /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
        attackType: 'SQL_INJECTION',
        severity: 'CRITICAL',
        confidence: 0.9,
        name: 'SQL Injection Basic',
      },
      {
        pattern: /(\<script)|(javascript\:)|(onclick\=)|(alert\(\))/i,
        attackType: 'XSS',
        severity: 'HIGH',
        confidence: 0.8,
        name: 'XSS Attempt',
      },
      {
        pattern: /(union select)|(select.*from)|(insert into)|(drop table)|(delete from)/i,
        attackType: 'SQL_INJECTION',
        severity: 'CRITICAL',
        confidence: 0.95,
        name: 'SQL Command',
      },
      {
        pattern: /(\.\.\/)|(\.\.\\\\)|(\/etc\/passwd)|(\/etc\/shadow)/i,
        attackType: 'PATH_TRAVERSAL',
        severity: 'HIGH',
        confidence: 0.85,
        name: 'Path Traversal',
      },
      {
        pattern: /(echo\s+\$\w+)|(cat\s+\/etc\/)|(ls\s+\-la)|(whoami)|(id)/i,
        attackType: 'COMMAND_INJECTION',
        severity: 'CRITICAL',
        confidence: 0.9,
        name: 'Command Injection',
      },
    ];

    for (const { pattern, attackType, severity, confidence, name } of patterns) {
      if (pattern.test(payload)) {
        return {
          isMalicious: true,
          attackType,
          severity,
          confidence,
          patternFound: name,
          matchedPattern: pattern.toString(),
        };
      }
    }

    return { isMalicious: false };
  }

  /**
   * Analyse une adresse IP
   */
  private async analyzeIP(ipAddress: string): Promise<IPAnalysis> {
    try {
      // Vérifier dans la base IOC
      const ioc = await this.prisma.ioc.findFirst({
        where: {
          type: 'IP_ADDRESS',
          value: ipAddress,
          isActive: true,
        },
      });

      if (ioc) {
        return {
          isMalicious: true,
          severity: ioc.severity,
          confidence: 0.9,
          attackType: 'MALICIOUS_IP',
          source: 'IOC_DATABASE',
          reason: ioc.description,
        };
      }

      // Vérifier dans la blacklist
      const blacklisted = await this.prisma.iPList.findFirst({
        where: {
          ipAddress,
          listType: 'BLACKLIST',
          isActive: true,
          OR: [
            { expiresAt: null },
            { expiresAt: { gt: new Date() } },
          ],
        },
      });

      if (blacklisted) {
        return {
          isMalicious: true,
          severity: 'HIGH',
          confidence: 0.8,
          attackType: 'BLACKLISTED_IP',
          source: 'IP_BLACKLIST',
          reason: blacklisted.reason,
        };
      }

      // Vérifier les patterns d'IPs internes/réservées
      if (this.isPrivateIP(ipAddress)) {
        return {
          isMalicious: false,
          isSuspicious: true,
          severity: 'LOW',
          confidence: 0.3,
          attackType: null,
          source: 'PRIVATE_IP',
          reason: 'Private IP address',
        };
      }

      return { isMalicious: false };
    } catch (error) {
      return { isMalicious: false, error: error.message };
    }
  }

  /**
   * Analyse le User-Agent
   */
  private analyzeUserAgent(userAgent: string): UserAgentAnalysis {
    const maliciousPatterns = [
      { pattern: /sqlmap/i, severity: 'HIGH', confidence: 0.9, type: 'SECURITY_SCANNER' },
      { pattern: /nikto/i, severity: 'HIGH', confidence: 0.9, type: 'SECURITY_SCANNER' },
      { pattern: /nmap/i, severity: 'HIGH', confidence: 0.8, type: 'SECURITY_SCANNER' },
      { pattern: /hydra/i, severity: 'HIGH', confidence: 0.9, type: 'BRUTE_FORCE_TOOL' },
      { pattern: /metasploit/i, severity: 'HIGH', confidence: 0.9, type: 'EXPLOITATION_TOOL' },
      { pattern: /burpsuite/i, severity: 'MEDIUM', confidence: 0.7, type: 'SECURITY_TESTING' },
    ];

    const suspiciousPatterns = [
      { pattern: /bot/i, severity: 'LOW', confidence: 0.4, type: 'BOT' },
      { pattern: /crawl/i, severity: 'LOW', confidence: 0.4, type: 'CRAWLER' },
      { pattern: /spider/i, severity: 'LOW', confidence: 0.4, type: 'SPIDER' },
      { pattern: /scraper/i, severity: 'LOW', confidence: 0.5, type: 'SCRAPER' },
      { pattern: /curl/i, severity: 'LOW', confidence: 0.3, type: 'CURL' },
      { pattern: /wget/i, severity: 'LOW', confidence: 0.3, type: 'WGET' },
    ];

    for (const { pattern, severity, confidence, type } of maliciousPatterns) {
      if (pattern.test(userAgent)) {
        return {
          isSuspicious: true,
          severity,
          confidence,
          type,
          patternFound: pattern.toString(),
        };
      }
    }

    for (const { pattern, severity, confidence, type } of suspiciousPatterns) {
      if (pattern.test(userAgent)) {
        return {
          isSuspicious: true,
          severity,
          confidence,
          type,
          patternFound: pattern.toString(),
        };
      }
    }

    return { isSuspicious: false };
  }

  /**
   * Analyse les codes d'erreur
   */
  private analyzeErrorCode(log: Log): ErrorAnalysis {
    if (!log.statusCode) return { isSuspicious: false };

    const suspiciousStatusCodes = {
      401: { severity: 'MEDIUM', confidence: 0.6, reason: 'Unauthorized access attempt' },
      403: { severity: 'MEDIUM', confidence: 0.6, reason: 'Forbidden access attempt' },
      404: { 
        severity: 'LOW', 
        confidence: 0.3, 
        reason: 'Not found - possible scanning',
        condition: (log: Log) => this.isSuspiciousEndpoint(log.endpoint),
      },
      500: { severity: 'MEDIUM', confidence: 0.5, reason: 'Server error - possible exploitation' },
      502: { severity: 'LOW', confidence: 0.2, reason: 'Bad gateway' },
      503: { severity: 'LOW', confidence: 0.2, reason: 'Service unavailable' },
    };

    const config = suspiciousStatusCodes[log.statusCode];
    if (config) {
      // Vérifier les conditions spéciales
      if (config.condition && !config.condition(log)) {
        return { isSuspicious: false };
      }

      return {
        isSuspicious: true,
        severity: config.severity,
        confidence: config.confidence,
        reason: config.reason,
        statusCode: log.statusCode,
      };
    }

    return { isSuspicious: false };
  }

  /**
   * Analyse le comportement
   */
  private async analyzeBehavior(log: Log): Promise<BehaviorAnalysis> {
    const analyses: BehaviorAnalysis[] = [];

    // 1. Vérifier la fréquence des requêtes
    const requestCount = await this.prisma.log.count({
      where: {
        ipAddress: log.ipAddress,
        timestamp: {
          gte: new Date(Date.now() - 5 * 60 * 1000), // 5 dernières minutes
        },
      },
    });

    if (requestCount > 100) {
      analyses.push({
        isSuspicious: true,
        severity: 'MEDIUM',
        confidence: 0.7,
        type: 'HIGH_FREQUENCY',
        reason: `High request frequency: ${requestCount} requests in 5 minutes`,
      });
    }

    // 2. Vérifier les tentatives sur endpoints sensibles
    const sensitiveEndpoints = ['/admin', '/login', '/api/auth', '/wp-admin', '/phpmyadmin'];
    if (log.endpoint && sensitiveEndpoints.some(ep => log.endpoint!.includes(ep))) {
      analyses.push({
        isSuspicious: true,
        severity: 'MEDIUM',
        confidence: 0.6,
        type: 'SENSITIVE_ENDPOINT',
        reason: `Access to sensitive endpoint: ${log.endpoint}`,
      });
    }

    // 3. Vérifier les heures inhabituelles (entre minuit et 5h)
    const hour = log.timestamp.getHours();
    if (hour >= 0 && hour <= 5) {
      const normalCount = await this.prisma.log.count({
        where: {
          ipAddress: log.ipAddress,
          timestamp: {
            gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // 30 jours
          },
        },
      });

      if (normalCount < 10) { // Nouvelle IP
        analyses.push({
          isSuspicious: true,
          severity: 'LOW',
          confidence: 0.4,
          type: 'UNUSUAL_TIME',
          reason: `Activity during unusual hours (${hour}:00) from new IP`,
        });
      }
    }

    // Retourner l'analyse la plus sévère
    if (analyses.length === 0) {
      return { isSuspicious: false };
    }

    return analyses.reduce((max, current) => 
      this.getSeverityValue(current.severity) > this.getSeverityValue(max.severity) ? current : max
    );
  }

  //= MÉTHODES UTILITAIRES 
  /**
   * Vérifie si un endpoint est suspect
   */
  private isSuspiciousEndpoint(endpoint: string | null): boolean {
    if (!endpoint) return false;
    
    const suspiciousPatterns = [
      /\.php$/,
      /\.asp$/,
      /\.aspx$/,
      /\.jsp$/,
      /\/cgi-bin\//,
      /\/wp-content\//,
      /\/\.git\//,
      /\/\.env$/,
      /\/config\./,
      /\/backup\//,
      /\/database\//,
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(endpoint));
  }

  /**
   * Vérifie si une IP est privée
   */
  private isPrivateIP(ip: string): boolean {
    const parts = ip.split('.').map(Number);
    
    // 10.0.0.0 - 10.255.255.255
    if (parts[0] === 10) return true;
    
    // 172.16.0.0 - 172.31.255.255
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    
    // 192.168.0.0 - 192.168.255.255
    if (parts[0] === 192 && parts[1] === 168) return true;
    
    // 127.0.0.0 - 127.255.255.255
    if (parts[0] === 127) return true;
    
    return false;
  }

  /**
   * Convertit une sévérité en valeur numérique
   */
  private getSeverityValue(severity: string): number {
    const values = {
      'LOW': 1,
      'MEDIUM': 2,
      'HIGH': 3,
      'CRITICAL': 4,
    };
    return values[severity] || 0;
  }

  /**
   * Construit la clause WHERE pour les recherches
   */
  private buildWhereClause(filters: LogFiltersDto): any {
    const where: any = {};

    // Filtres de date
    if (filters.startDate || filters.endDate) {
      where.timestamp = {};
      if (filters.startDate) where.timestamp.gte = new Date(filters.startDate);
      if (filters.endDate) where.timestamp.lte = new Date(filters.endDate);
    }

    // Filtre par IP
    if (filters.ipAddress) {
      where.ipAddress = { contains: filters.ipAddress };
    }

    // Filtre par endpoint
    if (filters.endpoint) {
      where.endpoint = { contains: filters.endpoint };
    }

    // Filtre par méthode HTTP
    if (filters.method) {
      where.method = filters.method;
    }

    // Filtre par code de statut
    if (filters.statusCode) {
      where.statusCode = filters.statusCode;
    }

    // Filtre par sévérité
    if (filters.severity?.length) {
      where.severity = { in: filters.severity };
    }

    // Filtre par type d'attaque
    if (filters.attackType?.length) {
      where.attackType = { in: filters.attackType };
    }

    // Filtre par application source
    if (filters.sourceApp) {
      where.sourceApp = filters.sourceApp;
    }

    // Filtre par menace
    if (filters.isMalicious !== undefined) {
      where.isMalicious = filters.isMalicious;
    }

    if (filters.isBlocked !== undefined) {
      where.isBlocked = filters.isBlocked;
    }

    // Recherche textuelle
    if (filters.search) {
      where.OR = [
        { endpoint: { contains: filters.search, mode: 'insensitive' } },
        { userAgent: { contains: filters.search, mode: 'insensitive' } },
        { requestBody: { contains: filters.search, mode: 'insensitive' } },
        { ipAddress: { contains: filters.search, mode: 'insensitive' } },
      ];
    }

    return where;
  }

  //= OPÉRATIONS BATCH

  /**
   * Importe plusieurs logs en batch
   */
  async importLogsBatch(logs: CreateLogDto[], sourceApp: string) {
    try {
      const batchSize = 100;
      const results = {
        imported: 0,
        skipped: 0,
        errors: 0,
        details: [] as any[],
      };

      for (let i = 0; i < logs.length; i += batchSize) {
        const batch = logs.slice(i, i + batchSize);
        
        const createdLogs = await Promise.allSettled(
          batch.map(log => this.createLog({
            ...log,
            sourceApp,
          }))
        );

        createdLogs.forEach((result, index) => {
          if (result.status === 'fulfilled') {
            results.imported++;
            results.details.push({
              index: i + index,
              status: 'IMPORTED',
              logId: result.value.id,
            });
          } else {
            results.errors++;
            results.details.push({
              index: i + index,
              status: 'ERROR',
              error: result.reason.message,
            });
          }
        });
      }

      return results;
    } catch (error) {
      throw new InternalServerErrorException('Batch import failed');
    }
  }

  /**
   * Met à jour plusieurs logs
   */
  async updateLogsBatch(updates: { id: string; data: UpdateLogDto }[]) {
    try {
      const results = await Promise.allSettled(
        updates.map(({ id, data }) =>
          this.prisma.log.update({
            where: { id },
            data,
          })
        )
      );

      return {
        updated: results.filter(r => r.status === 'fulfilled').length,
        failed: results.filter(r => r.status === 'rejected').length,
        details: results.map((result, index) => ({
          id: updates[index].id,
          status: result.status,
          error: result.status === 'rejected' ? result.reason.message : undefined,
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException('Batch update failed');
    }
  }

  //= STATISTIQUES 

  /**
   * Récupère les statistiques des logs
   */
  async getLogsStats(timeRange: '24h' | '7d' | '30d' = '24h') {
    try {
      const startDate = this.getStartDate(timeRange);
      
      const [
        totalLogs,
        bySeverity,
        bySourceApp,
        byAttackType,
        topIPs,
        topEndpoints,
        threatLevel,
      ] = await Promise.all([
        // Total logs
        this.prisma.log.count({
          where: { timestamp: { gte: startDate } },
        }),
        
        // Distribution par sévérité
        this.prisma.log.groupBy({
          by: ['severity'],
          where: { timestamp: { gte: startDate } },
          _count: { _all: true },
        }),
        
        // Distribution par application source
        this.prisma.log.groupBy({
          by: ['sourceApp'],
          where: { timestamp: { gte: startDate } },
          _count: { _all: true },
        }),
        
        // Distribution par type d'attaque
        this.prisma.log.groupBy({
          by: ['attackType'],
          where: { 
            timestamp: { gte: startDate },
            attackType: { not: null },
          },
          _count: { _all: true },
        }),
        
        // Top IPs
        this.prisma.log.groupBy({
          by: ['ipAddress'],
          where: { 
            timestamp: { gte: startDate },
            ipAddress: { not: null },
          },
          _count: { _all: true },
          orderBy: { _count: { _all: 'desc' } },
          take: 10,
        }),
        
        // Top endpoints
        this.prisma.log.groupBy({
          by: ['endpoint'],
          where: { 
            timestamp: { gte: startDate },
            endpoint: { not: null },
          },
          _count: { _all: true },
          orderBy: { _count: { _all: 'desc' } },
          take: 10,
        }),
        
        // Niveau de menace
        this.calculateThreatLevel(startDate),
      ]);

      return {
        timeRange,
        totalLogs,
        bySeverity: bySeverity.reduce((acc, item) => ({
          ...acc,
          [item.severity]: item._count._all,
        }), {}),
        bySourceApp: bySourceApp.reduce((acc, item) => ({
          ...acc,
          [item.sourceApp]: item._count._all,
        }), {}),
        byAttackType: byAttackType.reduce((acc, item) => ({
          ...acc,
          [item.attackType]: item._count._all,
        }), {}),
        topIPs: topIPs.map(ip => ({
          ip: ip.ipAddress,
          count: ip._count._all,
        })),
        topEndpoints: topEndpoints.map(ep => ({
          endpoint: ep.endpoint,
          count: ep._count._all,
        })),
        threatLevel,
        maliciousLogs: await this.prisma.log.count({
          where: { 
            timestamp: { gte: startDate },
            isMalicious: true,
          },
        }),
        blockedLogs: await this.prisma.log.count({
          where: { 
            timestamp: { gte: startDate },
            isBlocked: true,
          },
        }),
      };
    } catch (error) {
      throw new InternalServerErrorException('Failed to get logs statistics');
    }
  }

  /**
   * Calcule le niveau de menace
   */
  private async calculateThreatLevel(startDate: Date): Promise<number> {
    const [
      criticalLogs,
      highSeverityLogs,
      maliciousLogs,
      uniqueMaliciousIPs,
    ] = await Promise.all([
      this.prisma.log.count({
        where: {
          timestamp: { gte: startDate },
          severity: 'CRITICAL',
        },
      }),
      this.prisma.log.count({
        where: {
          timestamp: { gte: startDate },
          severity: 'HIGH',
        },
      }),
      this.prisma.log.count({
        where: {
          timestamp: { gte: startDate },
          isMalicious: true,
        },
      }),
      this.prisma.log.groupBy({
        by: ['ipAddress'],
        where: {
          timestamp: { gte: startDate },
          isMalicious: true,
          ipAddress: { not: null },
        },
      }).then(results => results.length),
    ]);

    // Calcul du score (0-10)
    let score = 0;
    score += criticalLogs * 2.5;
    score += highSeverityLogs * 1.5;
    score += maliciousLogs * 0.5;
    score += uniqueMaliciousIPs * 1.0;

    // Normalisation
    return Math.min(10, Math.round(score / 10 * 100) / 100);
  }

  //= OPÉRATIONS DE MAINTENANCE 

  /**
   * Nettoie les anciens logs
   */
  async cleanupOldLogs(retentionDays: number = 30) {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

      const deletedCount = await this.prisma.log.deleteMany({
        where: {
          timestamp: { lt: cutoffDate },
          severity: { in: ['LOW', 'INFO'] },
          isMalicious: false,
          isSuspicious: false,
        },
      });

      return {
        deleted: deletedCount.count,
        cutoffDate: cutoffDate.toISOString(),
      };
    } catch (error) {
      throw new InternalServerErrorException('Failed to cleanup old logs');
    }
  }

  /**
   * Réanalyse les logs non analysés
   */
  async reanalyzeLogs(batchSize: number = 100) {
    try {
      const logs = await this.prisma.log.findMany({
        where: {
          OR: [
            { analyzedAt: null },
            { analyzedAt: { lt: new Date(Date.now() - 24 * 60 * 60 * 1000) } },
          ],
          timestamp: { gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) },
        },
        take: batchSize,
        orderBy: { timestamp: 'desc' },
      });

      const results = {
        analyzed: 0,
        updated: 0,
        errors: 0,
      };

      for (const log of logs) {
        try {
          await this.analyzeLogAsync(log.id);
          results.analyzed++;
        } catch (error) {
          results.errors++;
        }
      }

      return results;
    } catch (error) {
      throw new InternalServerErrorException('Failed to reanalyze logs');
    }
  }

  //= MÉTHODES D'AIDE 
  private getStartDate(timeRange: '24h' | '7d' | '30d'): Date {
    const now = new Date();
    switch (timeRange) {
      case '24h':
        return new Date(now.getTime() - 24 * 60 * 60 * 1000);
      case '7d':
        return new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      case '30d':
        return new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      default:
        return new Date(now.getTime() - 24 * 60 * 60 * 1000);
    }
  }

  private async createAlertFromLog(log: Log, analysis: SecurityAnalysis) {
    // Implémentation de la création d'alerte
    // À intégrer avec le service d'alertes
  }

}


