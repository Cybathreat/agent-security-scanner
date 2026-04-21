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
    <div className="space-y-6">
      <h1 className="text-2xl font-mono font-bold">New Scan</h1>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target */}
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

        {/* Module Selection */}
        <Card>
          <CardHeader>
            <CardTitle>Modules</CardTitle>
            <CardDescription>Select scanner modules to run</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {allModules.map((mod) => (
                <label
                  key={mod.name}
                  className={`flex items-center gap-3 p-3 rounded-md border cursor-pointer transition-colors ${
                    selectedModules.includes(mod.name)
                      ? "border-primary bg-primary/5"
                      : "border-border hover:bg-muted"
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={selectedModules.includes(mod.name)}
                    onChange={() => toggleModule(mod.name)}
                    className="accent-primary"
                  />
                  <div>
                    <p className="text-sm font-mono font-medium">{mod.display_name}</p>
                    <p className="text-xs text-muted-foreground">{mod.category}</p>
                  </div>
                </label>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Quality Gate */}
        <Card>
          <CardHeader>
            <CardTitle>Quality Gate</CardTitle>
            <CardDescription>Configure when the quality gate should fail</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="text-sm font-mono text-muted-foreground">Fail on Severity</label>
              <select
                value={failOn}
                onChange={(e) => setFailOn(e.target.value)}
                className="mt-1 flex h-10 w-full rounded-md border border-border bg-input px-3 py-2 text-sm font-mono text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
            <div>
              <label className="text-sm font-mono text-muted-foreground">Timeout (seconds)</label>
              <Input
                type="number"
                value={timeout}
                onChange={(e) => setTimeout_(Number(e.target.value))}
                min={5}
                max={300}
                className="mt-1"
              />
            </div>
          </CardContent>
        </Card>

        {/* Submit */}
        <Button
          type="submit"
          disabled={!target || selectedModules.length === 0 || mutation.isPending}
          size="lg"
          className="w-full"
        >
          <ScanSearch className="h-4 w-4 mr-2" />
          {mutation.isPending ? "Starting..." : "Start Scan"}
        </Button>
      </form>
    </div>
  );
}