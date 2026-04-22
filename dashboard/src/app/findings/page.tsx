"use client";

import { useState } from "react";
import { useFindings } from "@/hooks/use-findings";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/findings/severity-badge";
import { FindingDetail } from "@/components/findings/finding-detail";
import { Skeleton } from "@/components/ui/skeleton";
import type { Severity, FindingResponse } from "@/lib/types";
import { SEVERITY_ORDER } from "@/lib/types";
import { Search, X } from "lucide-react";

const severityFilters: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export default function FindingsPage() {
  const [severityFilter, setSeverityFilter] = useState<Severity | "">("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedFinding, setSelectedFinding] = useState<FindingResponse | null>(null);
  const [offset, setOffset] = useState(0);

  const { data: findings, isLoading } = useFindings({
    severity: severityFilter || undefined,
    category: categoryFilter || undefined,
    search: searchQuery || undefined,
    limit: 50,
    offset,
  });

  const allFindings = findings ?? [];

  return (
    <div className="space-y-4">
      <h1 className="text-sm font-semibold">Findings</h1>

      {/* Filters */}
      <Card>
        <CardContent className="pt-3 space-y-3">
          <div className="flex flex-wrap gap-1">
            {severityFilters.map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(severityFilter === sev ? "" : sev)}
                className={`px-2 py-0.5 rounded border text-[11px] font-medium uppercase tracking-wider transition-colors ${
                  severityFilter === sev
                    ? "border-primary/30 bg-primary/5 text-primary"
                    : "border-border text-muted-foreground hover:bg-muted/50"
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          <div className="flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                placeholder="Search findings..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8"
              />
            </div>
            <Input
              placeholder="Category"
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="w-36"
            />
          </div>
        </CardContent>
      </Card>

      <div className="flex gap-4">
        {/* Findings list */}
        <div className="flex-1">
          <Card>
            <CardHeader>
              <CardTitle>{allFindings.length} Findings</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="space-y-2">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <Skeleton key={i} className="h-10 w-full" />
                  ))}
                </div>
              ) : allFindings.length === 0 ? (
                <p className="text-xs text-muted-foreground">No findings match your filters.</p>
              ) : (
                <div className="space-y-0.5">
                  {allFindings.map((f) => (
                    <button
                      key={f.id}
                      onClick={() => setSelectedFinding(f)}
                      className={`w-full text-left flex items-center justify-between p-2 rounded border transition-colors ${
                        selectedFinding?.id === f.id
                          ? "border-primary/30 bg-primary/5"
                          : "border-transparent hover:bg-muted/50"
                      }`}
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <SeverityBadge severity={f.severity} />
                        <div className="min-w-0">
                          <p className="text-xs font-medium truncate">{f.title}</p>
                          <p className="text-[11px] text-muted-foreground truncate">{f.category}</p>
                        </div>
                      </div>
                      {f.cwe && (
                        <Badge variant="outline" className="text-[10px] shrink-0">{f.cwe}</Badge>
                      )}
                    </button>
                  ))}
                </div>
              )}

              <div className="flex justify-center gap-2 mt-3">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setOffset(Math.max(0, offset - 50))}
                  disabled={offset === 0}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setOffset(offset + 50)}
                  disabled={allFindings.length < 50}
                >
                  Next
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Detail */}
        {selectedFinding && (
          <div className="w-80 shrink-0">
            <Card className="sticky top-4">
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle>Detail</CardTitle>
                <button
                  onClick={() => setSelectedFinding(null)}
                  className="text-muted-foreground hover:text-foreground transition-colors"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </CardHeader>
              <CardContent>
                <FindingDetail finding={selectedFinding} />
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}