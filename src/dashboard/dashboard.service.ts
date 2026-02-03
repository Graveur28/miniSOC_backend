import { CreateDashboardDto } from './dto/create-dashboard.dto';
import { UpdateDashboardDto } from './dto/update-dashboard.dto';
import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';



@Injectable()
export class DashboardService {

  private readonly logger = new Logger(DashboardService.name);

  constructor(private prisma: PrismaService) {}

  create(createDashboardDto: CreateDashboardDto) {
    return 'This action adds a new dashboard';
  }

  findAll() {
    return `This action returns all dashboard`;
  }

  findOne(id: number) {
    return `This action returns a #${id} dashboard`;
  }

  update(id: number, updateDashboardDto: UpdateDashboardDto) {
    return `This action updates a #${id} dashboard`;
  }

  remove(id: number) {
    return `This action removes a #${id} dashboard`;
  }

  /**
   * Récupère toutes les métriques du dashboard
   */
  async getDashboardMetrics(timeRange: '24h' | '7d' | '30d' = '24h') {
    try {
      const startDate = this.getStartDate(timeRange);
      
      // Exécuter toutes les requêtes en parallèle
      const [
        totalRequests,
        attacksBlocked,
        suspiciousIps,
        avgResponseTime,
        threatLevel,
        topAttackTypes,
        geoDistribution,
        alertStats,
        iocStats,
        recentLogs,
        recentAlerts,
        systemHealth,
      ] = await Promise.all([
        this.getTotalRequests(startDate),
        this.getAttacksBlocked(startDate),
        this.getSuspiciousIps(startDate),
        this.getAvgResponseTime(startDate),
        this.calculateThreatLevel(startDate),
        this.getTopAttackTypes(startDate),
        this.getGeoDistribution(startDate),
        this.getAlertStatistics(startDate),
        this.getIocStatistics(),
        this.getRecentLogs(10),
        this.getRecentAlerts(5),
        this.getSystemHealth(),
      ]);

      return {
        summary: {
          totalRequests,
          attacksBlocked,
          attackRate: totalRequests > 0 
            ? ((attacksBlocked / totalRequests) * 100).toFixed(2) + '%'
            : '0%',
          suspiciousIps,
          avgResponseTime: avgResponseTime ? avgResponseTime + 'ms' : 'N/A',
          threatLevel,
        },
        analytics: {
          topAttackTypes,
          geoDistribution,
          alertStats,
          iocStats,
        },
        recentActivity: {
          logs: recentLogs,
          alerts: recentAlerts,
        },
        system: systemHealth,
        timestamp: new Date().toISOString(),
        timeRange,
      };

    } catch (error) {
      this.logger.error(`Failed to get dashboard metrics: ${error.message}`, error.stack);
      throw new HttpException(
        'Failed to retrieve dashboard metrics',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Calcule le niveau de menace
   */
  private async calculateThreatLevel(startDate: Date): Promise<number> {
    try {
      const [
        criticalAlerts,
        highSeverityLogs,
        newIps,
        attackRate,
      ] = await Promise.all([
        // Alertes critiques
        this.prisma.alert.count({
          where: {
            severity: 'CRITICAL',
            createdAt: { gte: startDate },
            status: { in: ['NEW', 'IN_PROGRESS'] },
          },
        }),
        
        // Logs haute sévérité
        this.prisma.log.count({
          where: {
            severity: { in: ['HIGH', 'CRITICAL'] },
            timestamp: { gte: startDate },
          },
        }),
        
        // Nouvelles IPs suspectes
        this.prisma.log.groupBy({
          by: ['sourceIp'],
          where: {
            timestamp: { gte: startDate },
            severity: { in: ['MEDIUM', 'HIGH', 'CRITICAL'] },
          },
          having: {
            sourceIp: {
              _count: { _all: { lte: 5 } }, // Peu de requêtes = potentiellement nouveau
            },
          },
        }).then(results => results.length),
        
        // Taux d'attaque
        this.prisma.log.count({
          where: {
            timestamp: { gte: startDate },
            attackType: { not: null },
          },
        }).then(attackCount => {
          const totalCount = this.prisma.log.count({
            where: { timestamp: { gte: startDate } },
          });
          return totalCount.then(total => total > 0 ? attackCount / total : 0);
        }),
      ]);

      // Calcul du score de menace (0-10)
      let threatScore = 0;
      
      // Poids des facteurs
      threatScore += criticalAlerts * 2.5; // Chaque alerte critique = +2.5
      threatScore += highSeverityLogs * 0.1; // Chaque log haute sévérité = +0.1
      threatScore += newIps * 0.5; // Chaque nouvelle IP suspecte = +0.5
      threatScore += attackRate * 100; // Taux d'attaque en pourcentage
      
      // Normaliser entre 0 et 10
      const normalizedScore = Math.min(10, Math.max(0, threatScore / 10));
      
      return parseFloat(normalizedScore.toFixed(1));

    } catch (error) {
      this.logger.error(`Error calculating threat level: ${error.message}`);
      return 0;
    }
  }

  /**
   * Récupère le nombre total de requêtes
   */
  private async getTotalRequests(startDate: Date): Promise<number> {
    try {
      return await this.prisma.log.count({
        where: { timestamp: { gte: startDate } },
      });
    } catch (error) {
      this.logger.error(`Error getting total requests: ${error.message}`);
      return 0;
    }
  }

  /**
   * Récupère le nombre d'attaques bloquées
   */
  private async getAttacksBlocked(startDate: Date): Promise<number> {
    try {
      return await this.prisma.log.count({
        where: { 
          timestamp: { gte: startDate },
          isBlocked: true,
        },
      });
    } catch (error) {
      this.logger.error(`Error getting attacks blocked: ${error.message}`);
      return 0;
    }
  }

  /**
   * Récupère le nombre d'IPs suspectes
   */
  private async getSuspiciousIps(startDate: Date): Promise<number> {
    try {
      const result = await this.prisma.log.groupBy({
        by: ['sourceIp'],
        where: { 
          timestamp: { gte: startDate },
          severity: { in: ['MEDIUM', 'HIGH', 'CRITICAL'] },
        },
      });
      
      return result.length;
    } catch (error) {
      this.logger.error(`Error getting suspicious IPs: ${error.message}`);
      return 0;
    }
  }

  /**
   * Récupère le temps de réponse moyen
   */
  private async getAvgResponseTime(startDate: Date): Promise<number | null> {
    try {
      const result = await this.prisma.log.aggregate({
        where: { 
          timestamp: { gte: startDate },
          responseTime: { not: null },
        },
        _avg: { responseTime: true },
      });
      
      return result._avg.responseTime ? Math.round(result._avg.responseTime) : null;
    } catch (error) {
      this.logger.error(`Error getting average response time: ${error.message}`);
      return null;
    }
  }

  /**
   * Récupère les types d'attaque les plus courants
   */
  private async getTopAttackTypes(startDate: Date, limit: number = 5) {
    try {
      const results = await this.prisma.log.groupBy({
        by: ['attackType'],
        where: { 
          timestamp: { gte: startDate },
          attackType: { not: null },
        },
        _count: { _all: true },
        orderBy: { _count: { _all: 'desc' } },
        take: limit,
      });
      
      return results.map(result => ({
        type: result.attackType,
        count: result._count._all,
      }));
    } catch (error) {
      this.logger.error(`Error getting top attack types: ${error.message}`);
      return [];
    }
  }

  /**
   * Récupère la distribution géographique
   */
  private async getGeoDistribution(startDate: Date) {
    try {
      const results = await this.prisma.log.groupBy({
        by: ['countryCode'],
        where: { 
          timestamp: { gte: startDate },
          countryCode: { not: null },
        },
        _count: { _all: true },
        orderBy: { _count: { _all: 'desc' } },
        take: 10,
      });
      
      return results.map(result => ({
        country: result.countryCode,
        count: result._count._all,
        percentage: 0, // À calculer si nécessaire
      }));
    } catch (error) {
      this.logger.error(`Error getting geo distribution: ${error.message}`);
      return [];
    }
  }

  /**
   * Récupère les statistiques des alertes
   */
  private async getAlertStatistics(startDate: Date) {
    try {
      const [
        totalAlerts,
        bySeverity,
        byStatus,
        resolutionRate,
      ] = await Promise.all([
        this.prisma.alert.count({
          where: { createdAt: { gte: startDate } },
        }),
        
        this.prisma.alert.groupBy({
          by: ['severity'],
          where: { createdAt: { gte: startDate } },
          _count: { _all: true },
        }),
        
        this.prisma.alert.groupBy({
          by: ['status'],
          where: { createdAt: { gte: startDate } },
          _count: { _all: true },
        }),
        
        this.prisma.alert.count({
          where: { 
            createdAt: { gte: startDate },
            status: 'RESOLVED',
          },
        }).then(resolved => {
          return this.prisma.alert.count({
            where: { createdAt: { gte: startDate } },
          }).then(total => total > 0 ? (resolved / total) * 100 : 0);
        }),
      ]);
      
      return {
        total: totalAlerts,
        bySeverity: bySeverity.reduce((acc, item) => ({
          ...acc,
          [item.severity]: item._count._all,
        }), {}),
        byStatus: byStatus.reduce((acc, item) => ({
          ...acc,
          [item.status]: item._count._all,
        }), {}),
        resolutionRate: parseFloat(resolutionRate.toFixed(2)),
      };
    } catch (error) {
      this.logger.error(`Error getting alert statistics: ${error.message}`);
      return {
        total: 0,
        bySeverity: {},
        byStatus: {},
        resolutionRate: 0,
      };
    }
  }

  /**
   * Récupère les statistiques des IOC
   */
  private async getIocStatistics() {
    try {
      const [
        totalIocs,
        activeIocs,
        byType,
      ] = await Promise.all([
        this.prisma.ioc.count(),
        
        this.prisma.ioc.count({ where: { isActive: true } }),
        
        this.prisma.ioc.groupBy({
          by: ['type'],
          _count: { _all: true },
        }),
      ]);
      
      return {
        total: totalIocs,
        active: activeIocs,
        inactive: totalIocs - activeIocs,
        byType: byType.reduce((acc, item) => ({
          ...acc,
          [item.type]: item._count._all,
        }), {}),
      };
    } catch (error) {
      this.logger.error(`Error getting IOC statistics: ${error.message}`);
      return {
        total: 0,
        active: 0,
        inactive: 0,
        byType: {},
      };
    }
  }

  /**
   * Récupère les logs récents
   */
  private async getRecentLogs(limit: number = 10) {
    try {
      return await this.prisma.log.findMany({
        where: {
          severity: { in: ['HIGH', 'CRITICAL'] },
        },
        orderBy: { timestamp: 'desc' },
        take: limit,
        select: {
          id: true,
          timestamp: true,
          sourceIp: true,
          url: true,
          severity: true,
          attackType: true,
          isBlocked: true,
        },
      });
    } catch (error) {
      this.logger.error(`Error getting recent logs: ${error.message}`);
      return [];
    }
  }

  /**
   * Récupère les alertes récentes
   */
  private async getRecentAlerts(limit: number = 5) {
    try {
      return await this.prisma.alert.findMany({
        where: {
          status: { in: ['NEW', 'IN_PROGRESS'] },
        },
        orderBy: { createdAt: 'desc' },
        take: limit,
        select: {
          id: true,
          title: true,
          severity: true,
          status: true,
          ipAddress: true,
          createdAt: true,
          assignee: {
            select: { username: true },
          },
        },
      });
    } catch (error) {
      this.logger.error(`Error getting recent alerts: ${error.message}`);
      return [];
    }
  }

  /**
   * Vérifie la santé du système
   */
  private async getSystemHealth() {
    try {
      const [
        dbStatus,
        logCount24h,
        alertCount24h,
        avgResponseTime24h,
      ] = await Promise.all([
        // Vérification de la connexion DB
        this.prisma.$queryRaw`SELECT 1`.then(() => 'HEALTHY').catch(() => 'UNHEALTHY'),
        
        // Nombre de logs dans les 24h
        this.prisma.log.count({
          where: { timestamp: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } },
        }),
        
        // Nombre d'alertes dans les 24h
        this.prisma.alert.count({
          where: { createdAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } },
        }),
        
        // Temps de réponse moyen dans les 24h
        this.prisma.log.aggregate({
          where: { 
            timestamp: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
            responseTime: { not: null },
          },
          _avg: { responseTime: true },
        }).then(result => result._avg.responseTime || 0),
      ]);
      
      return {
        database: dbStatus,
        metrics: {
          logs24h: logCount24h,
          alerts24h: alertCount24h,
          avgResponseTime24h: Math.round(avgResponseTime24h),
        },
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
      };
    } catch (error) {
      this.logger.error(`Error getting system health: ${error.message}`);
      return {
        database: 'UNKNOWN',
        metrics: {
          logs24h: 0,
          alerts24h: 0,
          avgResponseTime24h: 0,
        },
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
      };
    }
  }

  /**
   * Récupère les tendances sur plusieurs périodes
   */
  async getTrends(metric: 'requests' | 'attacks' | 'alerts', periods: number = 7) {
    try {
      const trends = [];
      const now = new Date();
      
      for (let i = periods - 1; i >= 0; i--) {
        const startDate = new Date(now);
        startDate.setDate(startDate.getDate() - i - 1);
        
        const endDate = new Date(now);
        endDate.setDate(endDate.getDate() - i);
        
        let count = 0;
        
        switch (metric) {
          case 'requests':
            count = await this.prisma.log.count({
              where: { 
                timestamp: { 
                  gte: startDate,
                  lt: endDate,
                },
              },
            });
            break;
            
          case 'attacks':
            count = await this.prisma.log.count({
              where: { 
                timestamp: { 
                  gte: startDate,
                  lt: endDate,
                },
                attackType: { not: null },
              },
            });
            break;
            
          case 'alerts':
            count = await this.prisma.alert.count({
              where: { 
                createdAt: { 
                  gte: startDate,
                  lt: endDate,
                },
              },
            });
            break;
        }
        
        trends.push({
          date: startDate.toISOString().split('T')[0],
          value: count,
        });
      }
      
      return {
        metric,
        periods,
        trends,
        currentValue: trends[trends.length - 1]?.value || 0,
        previousValue: trends[trends.length - 2]?.value || 0,
        change: trends.length >= 2 
          ? ((trends[trends.length - 1].value - trends[trends.length - 2].value) / 
             (trends[trends.length - 2].value || 1) * 100).toFixed(1) + '%'
          : '0%',
      };
      
    } catch (error) {
      this.logger.error(`Error getting trends for ${metric}: ${error.message}`);
      throw new HttpException(
        'Failed to retrieve trends',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Récupère les recommandations basées sur les données
   */
  async getRecommendations() {
    try {
      const recommendations = [];
      const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
      
      // Vérifier les attaques brute force
      const bruteForceCount = await this.prisma.log.count({
        where: {
          timestamp: { gte: twentyFourHoursAgo },
          attackType: 'BRUTE_FORCE',
        },
      });
      
      if (bruteForceCount > 10) {
        recommendations.push({
          type: 'SECURITY',
          priority: 'HIGH',
          title: 'Multiple brute force attempts detected',
          description: `Found ${bruteForceCount} brute force attempts in the last 24 hours`,
          action: 'Implement rate limiting on authentication endpoints',
          details: {
            count: bruteForceCount,
            period: '24h',
            endpoints: await this.getTopBruteForceEndpoints(twentyFourHoursAgo),
          },
        });
      }
      
      // Vérifier les IPs avec beaucoup de requêtes
      const highVolumeIPs = await this.prisma.log.groupBy({
        by: ['sourceIp'],
        where: { timestamp: { gte: twentyFourHoursAgo } },
        _count: { _all: true },
        having: {
          sourceIp: {
            _count: { _all: { gt: 1000 } }, // Plus de 1000 requêtes en 24h
          },
        },
      });
      
      if (highVolumeIPs.length > 0) {
        recommendations.push({
          type: 'PERFORMANCE',
          priority: 'MEDIUM',
          title: 'High volume traffic from specific IPs',
          description: `${highVolumeIPs.length} IP(s) with over 1000 requests in 24 hours`,
          action: 'Consider implementing rate limiting or IP whitelisting',
          details: {
            ips: highVolumeIPs.map(ip => ({
              ip: ip.sourceIp,
              requestCount: ip._count._all,
            })),
          },
        });
      }
      
      // Vérifier les alertes non résolues
      const unresolvedCriticalAlerts = await this.prisma.alert.count({
        where: {
          severity: 'CRITICAL',
          status: { in: ['NEW', 'IN_PROGRESS'] },
          createdAt: { gte: new Date(Date.now() - 2 * 60 * 60 * 1000) }, // 2 heures
        },
      });
      
      if (unresolvedCriticalAlerts > 0) {
        recommendations.push({
          type: 'OPERATIONAL',
          priority: 'CRITICAL',
          title: 'Unresolved critical alerts',
          description: `${unresolvedCriticalAlerts} critical alert(s) pending for over 2 hours`,
          action: 'Immediate review and assignment required',
          details: {
            alertCount: unresolvedCriticalAlerts,
            timeframe: '2h',
          },
        });
      }
      
      // Vérifier la taille de la base de données
      const totalLogs = await this.prisma.log.count();
      if (totalLogs > 1000000) {
        recommendations.push({
          type: 'MAINTENANCE',
          priority: 'MEDIUM',
          title: 'Large log database',
          description: `Database contains ${totalLogs.toLocaleString()} logs`,
          action: 'Consider archiving old logs or implementing log rotation',
          details: {
            logCount: totalLogs,
            suggestion: 'Archive logs older than 30 days',
          },
        });
      }
      
      return recommendations;
      
    } catch (error) {
      this.logger.error(`Error generating recommendations: ${error.message}`);
      return [];
    }
  }

  /**
   * Récupère les endpoints ciblés par les attaques brute force
   */
  private async getTopBruteForceEndpoints(startDate: Date) {
    try {
      const results = await this.prisma.log.groupBy({
        by: ['url'],
        where: {
          timestamp: { gte: startDate },
          attackType: 'BRUTE_FORCE',
        },
        _count: { _all: true },
        orderBy: { _count: { _all: 'desc' } },
        take: 5,
      });
      
      return results.map(result => ({
        endpoint: result.url,
        attempts: result._count._all,
      }));
    } catch (error) {
      this.logger.error(`Error getting brute force endpoints: ${error.message}`);
      return [];
    }
  }

  /**
   * Calcule la date de début
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

