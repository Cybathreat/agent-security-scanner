/**
 * WebSocket client for real-time scan progress.
 */

import type { ScanEvent, ScanEventType } from "./types";

function getWsBase(): string {
  if (typeof window === "undefined") return "ws://localhost:8000/ws";
  if (process.env.NEXT_PUBLIC_WS_URL) return process.env.NEXT_PUBLIC_WS_URL;
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/ws`;
}

type EventHandler = (event: ScanEvent) => void;

export class ScanProgressWS {
  private ws: WebSocket | null = null;
  private handlers: Map<ScanEventType | "*", Set<EventHandler>> = new Map();
  private reconnectAttempts = 0;
  private maxReconnects = 5;
  private reconnectDelay = 1000;
  private scanId: string;
  private intentionalClose = false;

  constructor(scanId: string) {
    this.scanId = scanId;
  }

  connect(): void {
    const url = `${getWsBase()}/scans/${this.scanId}/progress`;
    this.ws = new WebSocket(url);

    this.ws.onopen = () => {
      this.reconnectAttempts = 0;
    };

    this.ws.onmessage = (event) => {
      try {
        const data: ScanEvent = JSON.parse(event.data);
        this.emit(data);
      } catch {
        // Ignore malformed messages
      }
    };

    this.ws.onclose = () => {
      if (!this.intentionalClose && this.reconnectAttempts < this.maxReconnects) {
        this.reconnectAttempts++;
        const delay = this.reconnectDelay * this.reconnectAttempts;
        setTimeout(() => this.connect(), delay);
      }
    };

    this.ws.onerror = () => {
      // onclose will handle reconnect
    };
  }

  disconnect(): void {
    this.intentionalClose = true;
    this.ws?.close();
    this.ws = null;
  }

  on(eventType: ScanEventType | "*", handler: EventHandler): () => void {
    if (!this.handlers.has(eventType)) {
      this.handlers.set(eventType, new Set());
    }
    this.handlers.get(eventType)!.add(handler);

    // Return unsubscribe function
    return () => {
      this.handlers.get(eventType)?.delete(handler);
    };
  }

  private emit(event: ScanEvent): void {
    // Specific handlers
    this.handlers.get(event.event)?.forEach((fn) => fn(event));
    // Wildcard handlers
    this.handlers.get("*")?.forEach((fn) => fn(event));
  }

  get connected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}