"use client";

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { startScan, listModules } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { ScanSearch } from "lucide-react";

const DEFAULT_MODULES = [
  "misconfigurations",
  "prompt_injection",
  "tool_boundaries",
  "rag_security",
  "secret_scanner",
];

export default function NewScanPage() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [target, setTarget] = useState("");
  const [selectedModules, setSelectedModules] = useState<string[]>(DEFAULT_MODULES);
  const [failOn, setFailOn] = useState("critical");
  const [timeout, setTimeout_] = useState(30);

  const { data: modules } = useQuery({
    queryKey: ["modules"],
    queryFn: listModules,
  });

  const mutation = useMutation({
    mutationFn: startScan,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      router.push(`/scans/${data.scan_id}`);
    },
  });

  const toggleModule = (name: string) => {
    setSelectedModules((prev) =>
      prev.includes(name) ? prev.filter((m) => m !== name) : [...prev, name],
    );
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!target) return;
    mutation.mutate({
      target,
      modules: selectedModules,
      timeout,
      fail_on_severity: failOn,
    });
  };

  const allModules = modules ?? [];

  return (
    <div className="space-y-4">
      <h1 className="text-sm font-semibold">New Scan</h1>

      <form onSubmit={handleSubmit} className="space-y-4">
        <Card>
          <CardHeader>
            <CardTitle>Target</CardTitle>
            <CardDescription>URL or API endpoint to scan</CardDescription>
          </CardHeader>
          <CardContent>
            <Input
              type="url"
              placeholder="https://api.example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              required
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Modules</CardTitle>
            <CardDescription>Select scanner modules to run</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 lg:grid-cols-3 gap-2">
              {allModules.map((mod) => (
                <label
                  key={mod.name}
                  className={`flex items-center gap-2 p-2 rounded border cursor-pointer transition-colors text-xs ${
                    selectedModules.includes(mod.name)
                      ? "border-primary/30 bg-primary/5 text-primary"
                      : "border-border hover:bg-muted/50 text-foreground"
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={selectedModules.includes(mod.name)}
                    onChange={() => toggleModule(mod.name)}
                    className="accent-primary h-3 w-3"
                  />
                  <div className="min-w-0">
                    <p className="font-medium truncate">{mod.display_name}</p>
                    <p className="text-[11px] text-muted-foreground truncate">{mod.category}</p>
                  </div>
                </label>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Quality Gate</CardTitle>
            <CardDescription>Configure when the quality gate should fail</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <label className="text-[11px] text-muted-foreground">Fail on Severity</label>
              <select
                value={failOn}
                onChange={(e) => setFailOn(e.target.value)}
                className="mt-0.5 flex h-8 w-full rounded border border-border bg-input px-2.5 py-1.5 text-xs text-foreground transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
            <div>
              <label className="text-[11px] text-muted-foreground">Timeout (seconds)</label>
              <Input
                type="number"
                value={timeout}
                onChange={(e) => setTimeout_(Number(e.target.value))}
                min={5}
                max={300}
                className="mt-0.5"
              />
            </div>
          </CardContent>
        </Card>

        <Button
          type="submit"
          disabled={!target || selectedModules.length === 0 || mutation.isPending}
          size="lg"
          className="w-full"
        >
          <ScanSearch className="h-3.5 w-3.5" />
          {mutation.isPending ? "Starting..." : "Start Scan"}
        </Button>
      </form>
    </div>
  );
}