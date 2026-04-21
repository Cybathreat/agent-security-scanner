"use client";

import { useQuery } from "@tanstack/react-query";
import { listScans, getScan } from "@/lib/api";

export function useScans(limit = 20, offset = 0) {
  return useQuery({
    queryKey: ["scans", limit, offset],
    queryFn: () => listScans(limit, offset),
  });
}

export function useScan(scanId: string | null) {
  return useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => getScan(scanId!),
    enabled: !!scanId,
    refetchInterval: (query) => {
      const data = query.state.data;
      // Poll running scans every 2s
      if (data && (data.status === "running" || data.status === "pending")) {
        return 2000;
      }
      return false;
    },
  });
}