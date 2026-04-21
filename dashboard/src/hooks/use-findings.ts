"use client";

import { useQuery } from "@tanstack/react-query";
import { listFindings } from "@/lib/api";

export function useFindings(params: {
  scan_id?: string;
  severity?: string;
  category?: string;
  search?: string;
  limit?: number;
  offset?: number;
} = {}) {
  return useQuery({
    queryKey: ["findings", params],
    queryFn: () => listFindings(params),
  });
}