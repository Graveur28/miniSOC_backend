import { CreateLogAnalyseurDto } from './dto/create-log-analyseur.dto';
import { UpdateLogAnalyseurDto } from './dto/update-log-analyseur.dto';

import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../prisma/prisma.service';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';


export interface LogEntry {
  id: number;
  timestamp: Date;
  level: string;
  source: string;
  message: string;
  ip_address?: string;
  user_id?: number;
  endpoint?: string;
  method?: string;
  status_code?: number;
  response_time?: number;
  user_agent?: string;
  metadata?: any;
}

export interface SecurityAnalysis {
  isMalicious: boolean;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  attackType?: string;
  confidence: number;
  reason: string;
  recommendations: string[];
}


@Injectable()
export class LogAnalyseurService {

  //private readonly logger = new Logger(LogAnalyzerService.name);
  //private lastProcessedId = 0;
  private readonly analysisCache = new Map<string, SecurityAnalysis>();

  constructor(
    private configService: ConfigService,
    private httpService: HttpService,
    private prisma: PrismaService,
  ) {
    this.initializeLastProcessedId();
  }


  /**
   * Initialise le dernier ID traité
   */
  private async initializeLastProcessedId() {
    try {
      const lastLog = await this.prisma.securityLog.findFirst({
        orderBy: { id: 'desc' },
        select: { originalLogId: true },
      });
      
      this.lastProcessedId = lastLog?.originalLogId || 0;
      this.logger.log(`Starting from log ID: ${this.lastProcessedId}`);
    } catch (error) {
      this.logger.error('Failed to initialize last processed ID', error);
    }
  }

  /**
   * Tâche planifiée - Analyse les nouveaux logs
   */
  @Cron(CronExpression.EVERY_30_SECONDS)
  async analyzeNewLogs() {
    try {
      this.logger.debug('Checking for new logs...');
      
      // Récupérer les nouveaux logs depuis la base de l'application
      const newLogs = await this.fetchNewLogs();
      
      if (newLogs.length === 0) {
        this.logger.debug('No new logs to analyze');
        return;
      }
      
      this.logger.log(`Found ${newLogs.length} new logs to analyze`);
      
      // Analyser chaque log
      for (const log of newLogs) {
        await this.analyzeSingleLog(log);
      }
      
      // Mettre à jour le dernier ID traité
      if (newLogs.length > 0) {
        this.lastProcessedId = newLogs[newLogs.length - 1].id;
      }
      
    } catch (error) {
      this.logger.error('Error analyzing new logs', error);
    }
  }

  /**
   * Récupère les nouveaux logs depuis la base de données de l'application
   */
  private async fetchNewLogs(): Promise<LogEntry[]> {
    try {
      const query = `
        SELECT * FROM application_logs 
        WHERE id > $1 
        ORDER BY id ASC 
        LIMIT 100
      `;
      
      // Utiliser une connexion directe à la base de données de l'application
      const result = await this.prisma.$queryRawUnsafe<LogEntry[]>(
        query,
        this.lastProcessedId,
      );
      
      return result;
      
    } catch (error) {
      this.logger.error('Failed to fetch new logs', error);
      return [];
    }
  }

  /**
   * Analyse un log individuel
   */
  private async analyzeSingleLog(log: LogEntry): Promise<void> {
    try {
      // Vérifier le cache
      const cacheKey = this.generateCacheKey(log);
      if (this.analysisCache.has(cacheKey)) {
        const cachedAnalysis = this.analysisCache.get(cacheKey)!;
        await this.saveSecurityLog(log, cachedAnalysis);
        return;
      }
      
      // Analyser le log
      const analysis = await this.performSecurityAnalysis(log);
      
      // Mettre en cache (5 minutes)
      this.analysisCache.set(cacheKey, analysis);
      setTimeout(() => this.analysisCache.delete(cacheKey), 5 * 60 * 1000);
      
      // Sauvegarder si malveillant
      if (analysis.isMalicious) {
        await this.saveSecurityLog(log, analysis);
        
        // Créer une alerte si nécessaire
        if (analysis.severity === 'HIGH' || analysis.severity === 'CRITICAL') {
          await this.createAlert(log, analysis);
        }
      }
      
    } catch (error) {
      this.logger.error(`Error analyzing log ${log.id}`, error);
    }
  }

  /**
   * Effectue l'analyse de sécurité
   */
  private async performSecurityAnalysis(log: LogEntry): Promise<SecurityAnalysis> {
    const analysis: SecurityAnalysis = {
      isMalicious: false,
      severity: 'LOW',
      confidence: 0,
      reason: '',
      recommendations: [],
    };
    
    // 1. Vérifier les patterns dans le message
    const messageAnalysis = this.analyzeMessage(log.message);
    if (messageAnalysis.isMalicious) {
      analysis.isMalicious = true;
      analysis.severity = messageAnalysis.severity;
      analysis.confidence = messageAnalysis.confidence;
      analysis.attackType = messageAnalysis.attackType;
      analysis.reason = `Malicious pattern in log message: ${messageAnalysis.pattern}`;
    }
    
    // 2. Vérifier les requêtes HTTP suspectes
    if (log.endpoint && log.method) {
      const httpAnalysis = this.analyzeHttpRequest(log);
      if (httpAnalysis.isMalicious && !analysis.isMalicious) {
        analysis.isMalicious = true;
        analysis.severity = httpAnalysis.severity;
        analysis.confidence = httpAnalysis.confidence;
        analysis.attackType = httpAnalysis.attackType;
        analysis.reason = httpAnalysis.reason;
      }
    }
    
    // 3. Vérifier les codes d'erreur
    if (log.status_code && log.status_code >= 400) {
      const errorAnalysis = this.analyzeErrorCode(log);
      if (errorAnalysis.isMalicious && !analysis.isMalicious) {
        analysis.isMalicious = true;
        analysis.severity = errorAnalysis.severity;
        analysis.confidence = errorAnalysis.confidence;
        analysis.attackType = errorAnalysis.attackType;
        analysis.reason = errorAnalysis.reason;
      }
    }
    
    // 4. Vérifier le user-agent
    if (log.user_agent) {
      const uaAnalysis = this.analyzeUserAgent(log.user_agent);
      if (uaAnalysis.isMalicious && !analysis.isMalicious) {
        analysis.isMalicious = true;
        analysis.severity = uaAnalysis.severity;
        analysis.confidence = uaAnalysis.confidence;
        analysis.attackType = uaAnalysis.attackType;
        analysis.reason = uaAnalysis.reason;
      }
    }
    
    // 5. Générer des recommandations
    analysis.recommendations = this.generateRecommendations(analysis, log);
    
    return analysis;
  }

  /**
   * Analyse le message du log
   */
  private analyzeMessage(message: string): any {
    const patterns = [
      {
        pattern: /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
        attackType: 'SQL_INJECTION',
        severity: 'CRITICAL' as const,
        confidence: 0.9,
      },
      {
        pattern: /(\<script)|(javascript\:)|(onclick\=)/i,
        attackType: 'XSS',
        severity: 'HIGH' as const,
        confidence: 0.8,
      },
      {
        pattern: /(union select)|(select.*from)|(insert into)|(drop table)/i,
        attackType: 'SQL_INJECTION',
        severity: 'CRITICAL' as const,
        confidence: 0.95,
      },
      {
        pattern: /(\.\.\/)|(\.\.\\\\)/,
        attackType: 'PATH_TRAVERSAL',
        severity: 'HIGH' as const,
        confidence: 0.85,
      },
      {
        pattern: /(password leaked)|(credentials exposed)|(sensitive data)/i,
        attackType: 'DATA_EXPOSURE',
        severity: 'CRITICAL' as const,
        confidence: 0.7,
      },
    ];
    
    for (const { pattern, attackType, severity, confidence } of patterns) {
      if (pattern.test(message)) {
        return {
          isMalicious: true,
          attackType,
          severity,
          confidence,
          pattern: pattern.toString(),
        };
      }
    }
    
    return { isMalicious: false };
  }

  /**
   * Analyse les requêtes HTTP
   */
  private analyzeHttpRequest(log: LogEntry): any {
    const suspiciousEndpoints = [
      '/admin',
      '/phpmyadmin',
      '/wp-admin',
      '/server-status',
      '/.env',
      '/.git',
      '/config',
      '/backup',
      '/database',
    ];
    
    const suspiciousMethods = ['POST', 'PUT', 'DELETE'];
    
    // Vérifier les endpoints sensibles
    if (log.endpoint && suspiciousEndpoints.some(ep => log.endpoint!.includes(ep))) {
      return {
        isMalicious: true,
        attackType: 'SCANNING',
        severity: 'MEDIUM' as const,
        confidence: 0.6,
        reason: `Access to sensitive endpoint: ${log.endpoint}`,
      };
    }
    
    // Vérifier les méthodes suspectes sur endpoints API
    if (log.endpoint?.includes('/api/') && suspiciousMethods.includes(log.method || '')) {
      return {
        isMalicious: true,
        attackType: 'API_ABUSE',
        severity: 'MEDIUM' as const,
        confidence: 0.5,
        reason: `Suspicious method ${log.method} on API endpoint`,
      };
    }
    
    return { isMalicious: false };
  }

  /**
   * Analyse les codes d'erreur
   */
  private analyzeErrorCode(log: LogEntry): any {
    if (!log.status_code) return { isMalicious: false };
    
    // 500 Internal Server Error - Peut indiquer une exploitation
    if (log.status_code === 500) {
      return {
        isMalicious: true,
        attackType: 'SERVER_ERROR',
        severity: 'MEDIUM' as const,
        confidence: 0.4,
        reason: 'Internal server error - possible exploitation attempt',
      };
    }
    
    // 401/403 - Accès non autorisé
    if (log.status_code === 401 || log.status_code === 403) {
      if (log.endpoint?.includes('/api/') || log.endpoint?.includes('/admin')) {
        return {
          isMalicious: true,
          attackType: 'UNAUTHORIZED_ACCESS',
          severity: 'HIGH' as const,
          confidence: 0.7,
          reason: `Unauthorized access attempt to ${log.endpoint}`,
        };
      }
    }
    
    // 404 - Endpoint non trouvé (scanning)
    if (log.status_code === 404) {
      if (this.isSuspiciousEndpoint(log.endpoint || '')) {
        return {
          isMalicious: true,
          attackType: 'SCANNING',
          severity: 'MEDIUM' as const,
          confidence: 0.6,
          reason: `Scanning attempt: ${log.endpoint}`,
        };
      }
    }
    
    return { isMalicious: false };
  }

  /**
   * Vérifie si un endpoint est suspect
   */
  private isSuspiciousEndpoint(endpoint: string): boolean {
    const suspiciousPatterns = [
      /\.php$/,
      /\.asp$/,
      /\.aspx$/,
      /\.jsp$/,
      /\/cgi-bin\//,
      /\/wp-content\//,
      /\.bak$/,
      /\.old$/,
      /\/\./,
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(endpoint));
  }

  /**
   * Analyse le user-agent
   */
  private analyzeUserAgent(userAgent: string): any {
    const maliciousAgents = [
      /sqlmap/i,
      /nikto/i,
      /nmap/i,
      /metasploit/i,
      /hydra/i,
      /burpsuite/i,
      /dirbuster/i,
      /gobuster/i,
      /wpscan/i,
    ];
    
    const suspiciousAgents = [
      /bot/i,
      /crawl/i,
      /spider/i,
      /scraper/i,
      /curl/i,
      /wget/i,
    ];
    
    for (const pattern of maliciousAgents) {
      if (pattern.test(userAgent)) {
        return {
          isMalicious: true,
          attackType: 'SECURITY_SCAN',
          severity: 'HIGH' as const,
          confidence: 0.9,
          reason: `Security tool detected: ${userAgent.substring(0, 50)}`,
        };
      }
    }
    
    for (const pattern of suspiciousAgents) {
      if (pattern.test(userAgent)) {
        return {
          isMalicious: true,
          attackType: 'BOT_ACTIVITY',
          severity: 'LOW' as const,
          confidence: 0.3,
          reason: `Bot activity detected: ${userAgent.substring(0, 50)}`,
        };
      }
    }
    
    return { isMalicious: false };
  }

  /**
   * Génère des recommandations
   */
  private generateRecommendations(analysis: SecurityAnalysis, log: LogEntry): string[] {
    const recommendations: string[] = [];
    
    if (analysis.attackType === 'SQL_INJECTION') {
      recommendations.push('Implement input validation and parameterized queries');
      recommendations.push('Review and sanitize all user inputs');
      recommendations.push('Consider using a WAF (Web Application Firewall)');
    }
    
    if (analysis.attackType === 'XSS') {
      recommendations.push('Implement output encoding for all user-generated content');
      recommendations.push('Use Content Security Policy (CSP) headers');
      recommendations.push('Validate and sanitize all user inputs');
    }
    
    if (analysis.attackType === 'SCANNING' || analysis.attackType === 'SECURITY_SCAN') {
      recommendations.push('Implement rate limiting on sensitive endpoints');
      recommendations.push('Consider blocking IPs with excessive 404 errors');
      recommendations.push('Use honey tokens to detect scanning activity');
    }
    
    if (analysis.attackType === 'UNAUTHORIZED_ACCESS') {
      recommendations.push('Review authentication and authorization mechanisms');
      recommendations.push('Implement multi-factor authentication for admin areas');
      recommendations.push('Monitor failed login attempts');
    }
    
    if (log.ip_address) {
      recommendations.push(`Investigate activity from IP: ${log.ip_address}`);
    }
    
    return recommendations;
  }

  /**
   * Sauvegarde le log de sécurité
   */
  private async saveSecurityLog(log: LogEntry, analysis: SecurityAnalysis) {
    try {
      await this.prisma.securityLog.create({
        data: {
          originalLogId: log.id,
          timestamp: log.timestamp,
          sourceIp: log.ip_address || 'Unknown',
          source: log.source,
          message: log.message.substring(0, 500),
          endpoint: log.endpoint,
          method: log.method,
          statusCode: log.status_code,
          severity: analysis.severity,
          attackType: analysis.attackType,
          confidence: analysis.confidence,
          reason: analysis.reason,
          isBlocked: false,
          analyzedAt: new Date(),
          metadata: {
            originalLog: {
              id: log.id,
              level: log.level,
              userAgent: log.user_agent,
              responseTime: log.response_time,
            },
            recommendations: analysis.recommendations,
          },
        },
      });
      
      this.logger.log(`Security log saved: ${log.id} - ${analysis.severity}`);
      
    } catch (error) {
      this.logger.error(`Failed to save security log ${log.id}`, error);
    }
  }

  /**
   * Crée une alerte
   */
  private async createAlert(log: LogEntry, analysis: SecurityAnalysis) {
    try {
      await this.prisma.alert.create({
        data: {
          title: `${analysis.attackType} detected`,
          description: analysis.reason,
          severity: analysis.severity,
          ipAddress: log.ip_address,
          attackType: analysis.attackType,
          confidence: analysis.confidence,
          metadata: {
            logId: log.id,
            endpoint: log.endpoint,
            method: log.method,
            statusCode: log.status_code,
            source: log.source,
          },
        },
      });
      
      this.logger.warn(`Alert created for log ${log.id}: ${analysis.attackType}`);
      
    } catch (error) {
      this.logger.error(`Failed to create alert for log ${log.id}`, error);
    }
  }

  /**
   * Génère une clé de cache
   */
  private generateCacheKey(log: LogEntry): string {
    return `${log.source}:${log.message.substring(0, 100)}:${log.ip_address}`;
  }

  /**
   * Récupère les logs analysés
   */
  async getSecurityLogs(options?: {
    startDate?: Date;
    endDate?: Date;
    severity?: string[];
    limit?: number;
    offset?: number;
  }) {
    try {
      const where: any = {};
      
      if (options?.startDate || options?.endDate) {
        where.timestamp = {};
        if (options.startDate) where.timestamp.gte = options.startDate;
        if (options.endDate) where.timestamp.lte = options.endDate;
      }
      
      if (options?.severity?.length) {
        where.severity = { in: options.severity };
      }
      
      const logs = await this.prisma.securityLog.findMany({
        where,
        orderBy: { timestamp: 'desc' },
        take: options?.limit || 100,
        skip: options?.offset || 0,
      });
      
      const total = await this.prisma.securityLog.count({ where });
      
      return {
        data: logs,
        meta: {
          total,
          limit: options?.limit || 100,
          offset: options?.offset || 0,
        },
      };
      
    } catch (error) {
      this.logger.error('Failed to fetch security logs', error);
      throw error;
    }
  }

  /**
   * Récupère les statistiques d'analyse
   */
  async getAnalysisStats(timeRange: '24h' | '7d' | '30d' = '24h') {
    try {
      const startDate = this.getStartDate(timeRange);
      
      const [
        totalLogs,
        maliciousLogs,
        bySeverity,
        byAttackType,
        topIPs,
        topEndpoints,
      ] = await Promise.all([
        // Total logs analysés
        this.prisma.securityLog.count({
          where: { timestamp: { gte: startDate } },
        }),
        
        // Logs malveillants
        this.prisma.securityLog.count({
          where: { 
            timestamp: { gte: startDate },
            severity: { in: ['MEDIUM', 'HIGH', 'CRITICAL'] },
          },
        }),
        
        // Distribution par sévérité
        this.prisma.securityLog.groupBy({
          by: ['severity'],
          where: { timestamp: { gte: startDate } },
          _count: { _all: true },
        }),
        
        // Distribution par type d'attaque
        this.prisma.securityLog.groupBy({
          by: ['attackType'],
          where: { 
            timestamp: { gte: startDate },
            attackType: { not: null },
          },
          _count: { _all: true },
        }),
        
        // Top IPs
        this.prisma.securityLog.groupBy({
          by: ['sourceIp'],
          where: { 
            timestamp: { gte: startDate },
            sourceIp: { not: null },
          },
          _count: { _all: true },
          orderBy: { _count: { _all: 'desc' } },
          take: 10,
        }),
        
        // Top endpoints
        this.prisma.securityLog.groupBy({
          by: ['endpoint'],
          where: { 
            timestamp: { gte: startDate },
            endpoint: { not: null },
          },
          _count: { _all: true },
          orderBy: { _count: { _all: 'desc' } },
          take: 10,
        }),
      ]);
      
      return {
        timeRange,
        totalLogs,
        maliciousLogs,
        maliciousRate: totalLogs > 0 
          ? ((maliciousLogs / totalLogs) * 100).toFixed(2) + '%'
          : '0%',
        bySeverity: bySeverity.reduce((acc, item) => ({
          ...acc,
          [item.severity]: item._count._all,
        }), {}),
        byAttackType: byAttackType.reduce((acc, item) => ({
          ...acc,
          [item.attackType]: item._count._all,
        }), {}),
        topIPs: topIPs.map(ip => ({
          ip: ip.sourceIp,
          count: ip._count._all,
        })),
        topEndpoints: topEndpoints.map(ep => ({
          endpoint: ep.endpoint,
          count: ep._count._all,
        })),
        lastAnalysisId: this.lastProcessedId,
        lastAnalysisTime: new Date().toISOString(),
      };
      
    } catch (error) {
      this.logger.error('Failed to get analysis stats', error);
      throw error;
    }
  }

  /**
   * Force l'analyse de logs spécifiques
   */
  async forceAnalysis(logIds: number[]) {
    try {
      this.logger.log(`Forcing analysis of ${logIds.length} logs`);
      
      const query = `
        SELECT * FROM application_logs 
        WHERE id = ANY($1::int[])
        ORDER BY id ASC
      `;
      
      const logs = await this.prisma.$queryRawUnsafe<LogEntry[]>(
        query,
        logIds,
      );
      
      let analyzedCount = 0;
      let alertCount = 0;
      
      for (const log of logs) {
        const analysis = await this.performSecurityAnalysis(log);
        
        if (analysis.isMalicious) {
          await this.saveSecurityLog(log, analysis);
          analyzedCount++;
          
          if (analysis.severity === 'HIGH' || analysis.severity === 'CRITICAL') {
            await this.createAlert(log, analysis);
            alertCount++;
          }
        }
      }
      
      return {
        analyzedLogs: analyzedCount,
        createdAlerts: alertCount,
        totalProcessed: logs.length,
      };
      
    } catch (error) {
      this.logger.error('Failed to force analysis', error);
      throw error;
    }
  }

  /**
   * Récupère la date de début
   */
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




}
