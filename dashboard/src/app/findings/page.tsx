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
    <div className="space-y-6">
      <h1 className="text-2xl font-mono font-bold">Findings Explorer</h1>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6 space-y-4">
          {/* Severity Chips */}
          <div className="flex flex-wrap gap-2">
            {severityFilters.map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(severityFilter === sev ? "" : sev)}
                className={`px-3 py-1 rounded-md border text-xs font-mono font-semibold uppercase transition-colors ${
                  severityFilter === sev
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border text-muted-foreground hover:bg-muted"
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Search + Category */}
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search findings..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <Input
              placeholder="Category filter"
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="w-48"
            />
          </div>
        </CardContent>
      </Card>

      <div className="flex gap-6">
        {/* Findings Table */}
        <div className="flex-1">
          <Card>
            <CardHeader>
              <CardTitle>{allFindings.length} Findings</CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="space-y-3">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <Skeleton key={i} className="h-14 w-full" />
                  ))}
                </div>
              ) : allFindings.length === 0 ? (
                <p className="text-sm text-muted-foreground">No findings match your filters.</p>
              ) : (
                <div className="space-y-2">
                  {allFindings.map((f) => (
                    <button
                      key={f.id}
                      onClick={() => setSelectedFinding(f)}
                      className={`w-full text-left flex items-center justify-between p-3 rounded-md border transition-colors ${
                        selectedFinding?.id === f.id
                          ? "border-primary bg-primary/5"
                          : "border-border hover:bg-muted"
                      }`}
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <SeverityBadge severity={f.severity} />
                        <div className="min-w-0">
                          <p className="text-sm font-mono font-medium truncate">{f.title}</p>
                          <p className="text-xs text-muted-foreground truncate">{f.category}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {f.cwe && (
                          <Badge variant="outline" className="text-xs">{f.cwe}</Badge>
                        )}
                      </div>
                    </button>
                  ))}
                </div>
              )}

              {/* Pagination */}
              <div className="flex justify-center gap-2 mt-4">
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

        {/* Detail Panel */}
        {selectedFinding && (
          <div className="w-96 shrink-0">
            <Card className="sticky top-6">
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle>Finding Detail</CardTitle>
                <button
                  onClick={() => setSelectedFinding(null)}
                  className="text-muted-foreground hover:text-foreground"
                >
                  <X className="h-4 w-4" />
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