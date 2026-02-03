import { CreateAlerteDto } from './dto/create-alerte.dto';
import { UpdateAlerteDto } from './dto/update-alerte.dto';

import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';
import { CreateAlertDto } from './dto/create-alert.dto';
import { UpdateAlertDto } from './dto/update-alert.dto';
import { AlertFilterDto } from './dto/alert-filter.dto';
import { EventEmitter2 } from '@nestjs/event-emitter';



@Injectable()
export class AlerteService {
  private readonly logger = new Logger(AlertsService.name);

  constructor(
    private prisma: PrismaService,
    private eventEmitter: EventEmitter2,
  ) {}


   /**
   * Crée une nouvelle alerte
   */
  async create(createAlertDto: CreateAlertDto) {
    try {
      // Vérifier s'il y a une alerte similaire récente
      const existingAlert = await this.findSimilarAlert(createAlertDto);
      
      if (existingAlert) {
        this.logger.log(`Updating existing alert: ${existingAlert.id}`);
        return this.updateExistingAlert(existingAlert.id, createAlertDto);
      }
      
      // Créer une nouvelle alerte
      const alert = await this.prisma.alert.create({
        data: {
          ...createAlertDto,
          startedAt: createAlertDto.startedAt || new Date(),
          status: createAlertDto.status || 'NEW',
          confidence: createAlertDto.confidence || 0.7,
          metadata: createAlertDto.metadata || {},
        },
        include: {
          assignee: {
            select: { id: true, username: true, role: true },
          },
        },
      });

      // Émettre un événement pour les notifications
      this.eventEmitter.emit('alert.created', alert);
      
      this.logger.log(`Alert created: ${alert.id} - ${alert.title}`);
      return alert;

    } catch (error) {
      this.logger.error(`Failed to create alert: ${error.message}`, error.stack);
      
      if (error.code === 'P2002') {
        throw new HttpException(
          'Alert with similar data already exists',
          HttpStatus.CONFLICT,
        );
      }
      
      throw new HttpException(
        'Failed to create alert',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Récupère toutes les alertes avec filtres
   */
  async findAll(filters?: AlertFilterDto) {
    try {
      const where = this.buildWhereClause(filters);
      
      const alerts = await this.prisma.alert.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: filters?.limit || 50,
        skip: filters?.skip || 0,
        include: {
          assignee: {
            select: { id: true, username: true, role: true },
          },
          logs: {
            take: 5,
            orderBy: { timestamp: 'desc' },
          },
          _count: {
            select: { logs: true, comments: true, actions: true },
          },
        },
      });

      return {
        data: alerts,
        meta: {
          total: await this.prisma.alert.count({ where }),
          limit: filters?.limit || 50,
          skip: filters?.skip || 0,
        },
      };

    } catch (error) {
      this.logger.error(`Failed to fetch alerts: ${error.message}`);
      throw new HttpException(
        'Failed to retrieve alerts',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Récupère une alerte par son ID
   */
  async findOne(id: string) {
    try {
      const alert = await this.prisma.alert.findUnique({
        where: { id },
        include: {
          assignee: {
            select: { id: true, username: true, email: true, role: true },
          },
          logs: {
            orderBy: { timestamp: 'desc' },
            take: 100,
          },
          comments: {
            orderBy: { createdAt: 'desc' },
            include: {
              user: {
                select: { id: true, username: true },
              },
            },
          },
          actions: {
            orderBy: { performedAt: 'desc' },
            include: {
              performedBy: {
                select: { id: true, username: true },
              },
            },
          },
        },
      });

      if (!alert) {
        throw new HttpException('Alert not found', HttpStatus.NOT_FOUND);
      }

      return alert;

    } catch (error) {
      if (error instanceof HttpException) throw error;
      
      this.logger.error(`Failed to fetch alert ${id}: ${error.message}`);
      throw new HttpException(
        'Failed to retrieve alert',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Met à jour une alerte
   */
  async update(id: string, updateAlertDto: UpdateAlertDto) {
    try {
      const alert = await this.prisma.alert.update({
        where: { id },
        data: updateAlertDto,
        include: {
          assignee: {
            select: { id: true, username: true },
          },
        },
      });

      // Émettre un événement si le statut a changé
      if (updateAlertDto.status) {
        this.eventEmitter.emit('alert.updated', {
          alertId: id,
          newStatus: updateAlertDto.status,
          previousStatus: alert.status,
        });
      }

      this.logger.log(`Alert updated: ${id}`);
      return alert;

    } catch (error) {
      if (error.code === 'P2025') {
        throw new HttpException('Alert not found', HttpStatus.NOT_FOUND);
      }
      
      this.logger.error(`Failed to update alert ${id}: ${error.message}`);
      throw new HttpException(
        'Failed to update alert',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Supprime une alerte
   */
  async remove(id: string) {
    try {
      await this.prisma.alert.delete({
        where: { id },
      });

      this.eventEmitter.emit('alert.deleted', { alertId: id });
      
      this.logger.log(`Alert deleted: ${id}`);
      return { message: 'Alert deleted successfully' };

    } catch (error) {
      if (error.code === 'P2025') {
        throw new HttpException('Alert not found', HttpStatus.NOT_FOUND);
      }
      
      this.logger.error(`Failed to delete alert ${id}: ${error.message}`);
      throw new HttpException(
        'Failed to delete alert',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Assign une alerte à un utilisateur
   */
  async assignAlert(alertId: string, userId: string) {
    try {
      const alert = await this.prisma.alert.update({
        where: { id: alertId },
        data: {
          assigneeId: userId,
          status: 'IN_PROGRESS',
        },
        include: {
          assignee: {
            select: { id: true, username: true },
          },
        },
      });

      // Créer une action d'assignation
      await this.prisma.alertAction.create({
        data: {
          alertId,
          actionType: 'ASSIGN',
          description: `Alert assigned to ${alert.assignee.username}`,
          performedById: userId,
        },
      });

      this.eventEmitter.emit('alert.assigned', {
        alertId,
        assigneeId: userId,
      });

      this.logger.log(`Alert ${alertId} assigned to user ${userId}`);
      return alert;

    } catch (error) {
      if (error.code === 'P2025') {
        throw new HttpException('Alert not found', HttpStatus.NOT_FOUND);
      }
      
      this.logger.error(`Failed to assign alert ${alertId}: ${error.message}`);
      throw new HttpException(
        'Failed to assign alert',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Résout une alerte
   */
  async resolveAlert(alertId: string, userId: string, resolutionNotes?: string) {
    try {
      const alert = await this.prisma.alert.update({
        where: { id: alertId },
        data: {
          status: 'RESOLVED',
          resolvedAt: new Date(),
        },
      });

      // Créer une action de résolution
      await this.prisma.alertAction.create({
        data: {
          alertId,
          actionType: 'RESOLVE',
          description: `Alert resolved${resolutionNotes ? ': ' + resolutionNotes : ''}`,
          performedById: userId,
          metadata: {
            resolutionNotes,
            resolvedAt: new Date().toISOString(),
          },
        },
      });

      // Ajouter un commentaire de résolution
      if (resolutionNotes) {
        await this.prisma.comment.create({
          data: {
            alertId,
            userId,
            content: `Resolved: ${resolutionNotes}`,
          },
        });
      }

      this.eventEmitter.emit('alert.resolved', {
        alertId,
        resolvedBy: userId,
      });

      this.logger.log(`Alert ${alertId} resolved by user ${userId}`);
      return alert;

    } catch (error) {
      if (error.code === 'P2025') {
        throw new HttpException('Alert not found', HttpStatus.NOT_FOUND);
      }
      
      this.logger.error(`Failed to resolve alert ${alertId}: ${error.message}`);
      throw new HttpException(
        'Failed to resolve alert',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Récupère les statistiques des alertes
   */
  async getAlertStats(timeRange: '24h' | '7d' | '30d' = '24h') {
    try {
      const startDate = this.getStartDate(timeRange);
      
      const [
        totalAlerts,
        bySeverity,
        byStatus,
        byAttackType,
        resolutionTime,
        unassignedCount,
      ] = await Promise.all([
        // Total des alertes
        this.prisma.alert.count({
          where: { createdAt: { gte: startDate } },
        }),
        
        // Distribution par sévérité
        this.prisma.alert.groupBy({
          by: ['severity'],
          where: { createdAt: { gte: startDate } },
          _count: { _all: true },
        }),
        
        // Distribution par statut
        this.prisma.alert.groupBy({
          by: ['status'],
          where: { createdAt: { gte: startDate } },
          _count: { _all: true },
        }),
        
        // Distribution par type d'attaque
        this.prisma.alert.groupBy({
          by: ['attackType'],
          where: { 
            createdAt: { gte: startDate },
            attackType: { not: null },
          },
          _count: { _all: true },
        }),
        
        // Temps moyen de résolution
        this.prisma.alert.aggregate({
          where: {
            status: 'RESOLVED',
            resolvedAt: { not: null },
            startedAt: { not: null },
          },
          _avg: {
            resolutionTime: {
              $queryRaw: 'EXTRACT(EPOCH FROM (resolved_at - started_at))',
            },
          },
        }),
        
        // Alertes non assignées
        this.prisma.alert.count({
          where: {
            createdAt: { gte: startDate },
            assigneeId: null,
            status: { in: ['NEW', 'IN_PROGRESS'] },
          },
        }),
      ]);

      return {
        timeRange,
        totalAlerts,
        severityDistribution: bySeverity.reduce((acc, item) => ({
          ...acc,
          [item.severity]: item._count._all,
        }), {}),
        statusDistribution: byStatus.reduce((acc, item) => ({
          ...acc,
          [item.status]: item._count._all,
        }), {}),
        attackTypeDistribution: byAttackType.reduce((acc, item) => ({
          ...acc,
          [item.attackType]: item._count._all,
        }), {}),
        averageResolutionTime: resolutionTime._avg.resolutionTime 
          ? Math.round(resolutionTime._avg.resolutionTime / 60) // Convertir en minutes
          : null,
        unassignedAlerts: unassignedCount,
      };

    } catch (error) {
      this.logger.error(`Failed to get alert statistics: ${error.message}`);
      throw new HttpException(
        'Failed to retrieve alert statistics',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  /**
   * Recherche une alerte similaire
   */
  private async findSimilarAlert(createAlertDto: CreateAlertDto) {
    try {
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
      
      return await this.prisma.alert.findFirst({
        where: {
          ipAddress: createAlertDto.ipAddress,
          attackType: createAlertDto.attackType,
          severity: createAlertDto.severity,
          status: { in: ['NEW', 'IN_PROGRESS'] },
          createdAt: { gte: oneHourAgo },
        },
        orderBy: { createdAt: 'desc' },
      });
      
    } catch (error) {
      this.logger.error(`Error finding similar alert: ${error.message}`);
      return null;
    }
  }

  /**
   * Met à jour une alerte existante
   */
  private async updateExistingAlert(alertId: string, updateData: CreateAlertDto) {
    try {
      const alert = await this.prisma.alert.update({
        where: { id: alertId },
        data: {
          // Mettre à jour les métadonnées
          metadata: {
            $merge: updateData.metadata || {},
          },
          // Incrémenter le compteur de confiance
          confidence: {
            increment: 0.1,
          },
          // Mettre à jour la date de dernière vue
          updatedAt: new Date(),
        },
      });

      this.eventEmitter.emit('alert.updated', {
        alertId,
        type: 'MERGED',
      });

      return alert;
      
    } catch (error) {
      this.logger.error(`Failed to update existing alert: ${error.message}`);
      throw error;
    }
  }

  /**
   * Construit la clause WHERE pour les filtres
   */
  private buildWhereClause(filters?: AlertFilterDto): any {
    const where: any = {};
    
    if (filters?.startDate || filters?.endDate) {
      where.createdAt = {};
      if (filters.startDate) where.createdAt.gte = new Date(filters.startDate);
      if (filters.endDate) where.createdAt.lte = new Date(filters.endDate);
    }
    
    if (filters?.severity?.length) {
      where.severity = { in: filters.severity };
    }
    
    if (filters?.status?.length) {
      where.status = { in: filters.status };
    }
    
    if (filters?.attackType?.length) {
      where.attackType = { in: filters.attackType };
    }
    
    if (filters?.ip) {
      where.ipAddress = { contains: filters.ip };
    }
    
    if (typeof filters?.assignedToMe === 'boolean' && filters.assignedToMe) {
      where.assigneeId = filters.userId; // À remplacer par l'ID utilisateur réel
    }
    
    if (filters?.search) {
      where.OR = [
        { title: { contains: filters.search, mode: 'insensitive' } },
        { description: { contains: filters.search, mode: 'insensitive' } },
      ];
    }
    
    return where;
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


