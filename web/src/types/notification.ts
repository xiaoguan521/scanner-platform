// In-app notifications and Webhook delivery.
export type NotificationSeverity = 'info' | 'warning' | 'error';

export interface Notification {
  id: string;
  kind: string;
  severity: NotificationSeverity;
  title: string;
  message: string;
  objectType: string;
  objectId: string;
  createdAt: string;
  readAt?: string;
}

export interface NotificationList {
  items: Notification[];
  total: number;
  unreadCount: number;
}

export interface NotificationListPage extends NotificationList {
  page: number;
  pageSize: number;
}

export interface NotificationSettings {
  webhookEnabled: boolean;
  webhookUrl: string;
}

export interface NotificationDelivery {
  id: string;
  notificationId: string;
  state: 'PENDING' | 'SENDING' | 'FAILED' | 'DELIVERED' | 'DEAD';
  attempts: number;
  nextAttemptAt: string;
  lastError?: string;
  deliveredAt?: string;
  createdAt: string;
}

export interface NotificationDeliveryList {
  items: NotificationDelivery[];
  total: number;
}
