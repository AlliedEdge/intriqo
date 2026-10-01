/**
 * Intriqo WebSocket Client
 * Real-time event streaming interface for detections and agent activity.
 */

export type EventHandler<T = unknown> = (data: T) => void;

export class EventStreamClient {
  private ws: WebSocket | null = null;
  private handlers: Map<string, Set<EventHandler>> = new Map();

  constructor(private url: string = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/events`) {}

  connect(): void {
    this.ws = new WebSocket(this.url);

    this.ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        const eventType = payload.type || 'message';
        const listeners = this.handlers.get(eventType);
        if (listeners) {
          listeners.forEach((handler) => handler(payload.data));
        }
      } catch (err) {
        console.error('Failed to parse WebSocket message:', err);
      }
    };
  }

  on<T>(eventType: string, handler: EventHandler<T>): () => void {
    if (!this.handlers.has(eventType)) {
      this.handlers.set(eventType, new Set());
    }
    this.handlers.get(eventType)!.add(handler as EventHandler);

    return () => {
      this.handlers.get(eventType)?.delete(handler as EventHandler);
    };
  }

  disconnect(): void {
    this.ws?.close();
    this.ws = null;
  }
}
