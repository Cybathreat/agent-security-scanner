"use client";

import { useEffect, useRef, useState } from "react";
import { ScanProgressWS } from "@/lib/ws";
import type { ScanEvent, ScanEventType } from "@/lib/types";

export function useScanProgress(scanId: string | null) {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<ScanProgressWS | null>(null);

  useEffect(() => {
    if (!scanId) return;

    const ws = new ScanProgressWS(scanId);
    wsRef.current = ws;

    ws.on("*", (event) => {
      setEvents((prev) => [...prev, event]);

      if (event.event === "scan_completed" || event.event === "scan_error") {
        ws.disconnect();
        setConnected(false);
      }
    });

    ws.on("connected", () => {
      setConnected(true);
    });

    ws.connect();
    setConnected(true); // optimistic

    return () => {
      ws.disconnect();
      setConnected(false);
    };
  }, [scanId]);

  const clearEvents = () => setEvents([]);

  return { events, connected, clearEvents };
}