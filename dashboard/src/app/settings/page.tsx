"use client";

import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getConfig, updateConfig, listModules } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Settings, Copy, Check } from "lucide-react";

export default function SettingsPage() {
  const queryClient = useQueryClient();
  const { data: config, isLoading } = useQuery({ queryKey: ["config"], queryFn: getConfig });
  const { data: modules } = useQuery({ queryKey: ["modules"], queryFn: listModules });

  const [failOn, setFailOn] = useState("critical");
  const [maxFindings, setMaxFindings] = useState("");
  const [maxRiskScore, setMaxRiskScore] = useState("");
  const [copiedYaml, setCopiedYaml] = useState<string | null>(null);

  useEffect(() => {
    if (config?.quality_gate) {
      setFailOn((config.quality_gate as Record<string, unknown>).fail_on_severity as string || "critical");
      setMaxFindings((config.quality_gate as Record<string, unknown>).max_findings?.toString() || "");
      setMaxRiskScore((config.quality_gate as Record<string, unknown>).max_risk_score?.toString() || "");
    }
  }, [config]);

  const updateMutation = useMutation({
    mutationFn: updateConfig,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["config"] }),
  });

  const handleSave = () => {
    updateMutation.mutate({
      quality_gate: {
        fail_on_severity: failOn,
        ...(maxFindings ? { max_findings: parseInt(maxFindings) } : {}),
        ...(maxRiskScore ? { max_risk_score: parseInt(maxRiskScore) } : {}),
      },
    });
  };

  const handleModuleToggle = (moduleName: string, enabled: boolean) => {
    updateMutation.mutate({ modules: { [moduleName]: { enabled } } });
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedYaml(id);
    setTimeout(() => setCopiedYaml(null), 2000);
  };

  const githubActionsYaml = `name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install scanner
        run: pip install singularity
      - name: Run scan
        run: |
          singularity scan \\
            --target \${{ secrets.TARGET_URL }} \\
            --fail-on critical \\
            --format json \\
            --output reports/`;

  const gitlabCiYaml = `security_scan:
  stage: test
  image: python:3.12
  script:
    - pip install singularity
    - singularity scan
        --target $TARGET_URL
        --fail-on critical
        --format json
        --output reports/
  artifacts:
    paths:
      - reports/`;

  const cliCommand = `singularity scan \\
  --target https://api.example.com \\
  --modules prompt_injection,rag_security \\
  --fail-on critical \\
  --max-findings 50 \\
  --max-risk-score 100 \\
  --format both \\
  --output reports/`;

  const selectClass = "mt-0.5 flex h-8 w-full rounded border border-border bg-input px-2.5 py-1.5 text-xs text-foreground transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1";

  return (
    <div className="space-y-4">
      <h1 className="text-sm font-semibold flex items-center gap-1.5">
        <Settings className="h-4 w-4" />
        Settings
      </h1>

      {isLoading ? (
        <div className="space-y-3">
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-36 w-full" />
          <Skeleton className="h-48 w-full" />
        </div>
      ) : (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Quality Gate</CardTitle>
              <CardDescription>Configure thresholds</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div>
                <label className="text-[11px] text-muted-foreground">Fail on Severity</label>
                <select value={failOn} onChange={(e) => setFailOn(e.target.value)} className={selectClass}>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] text-muted-foreground">Max Findings</label>
                  <Input type="number" placeholder="No limit" value={maxFindings} onChange={(e) => setMaxFindings(e.target.value)} className="mt-0.5" />
                </div>
                <div>
                  <label className="text-[11px] text-muted-foreground">Max Risk Score</label>
                  <Input type="number" placeholder="No limit" value={maxRiskScore} onChange={(e) => setMaxRiskScore(e.target.value)} className="mt-0.5" />
                </div>
              </div>
              <Button onClick={handleSave} disabled={updateMutation.isPending} size="sm">
                {updateMutation.isPending ? "Saving..." : "Save"}
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Modules</CardTitle>
              <CardDescription>Scanner modules</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 lg:grid-cols-3 gap-2">
                {(modules ?? []).map((mod) => (
                  <div key={mod.name} className={`flex items-center justify-between p-2 rounded border text-xs transition-colors ${
                    mod.enabled ? "border-primary/30 bg-primary/5" : "border-border"
                  }`}>
                    <div className="min-w-0">
                      <p className="font-medium truncate">{mod.display_name}</p>
                      <p className="text-[11px] text-muted-foreground truncate">{mod.category}</p>
                    </div>
                    <button
                      onClick={() => handleModuleToggle(mod.name, !mod.enabled)}
                      className={`px-2 py-0.5 text-[11px] rounded font-medium ${
                        mod.enabled ? "bg-primary/10 text-primary" : "bg-muted text-muted-foreground"
                      }`}
                    >
                      {mod.enabled ? "ON" : "OFF"}
                    </button>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>CI/CD Integration</CardTitle>
              <CardDescription>Pipeline configurations</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <p className="text-xs font-medium">GitHub Actions</p>
                  <Button variant="ghost" size="sm" onClick={() => copyToClipboard(githubActionsYaml, "github")}>
                    {copiedYaml === "github" ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                  </Button>
                </div>
                <div className="terminal-output">{githubActionsYaml}</div>
              </div>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <p className="text-xs font-medium">GitLab CI</p>
                  <Button variant="ghost" size="sm" onClick={() => copyToClipboard(gitlabCiYaml, "gitlab")}>
                    {copiedYaml === "gitlab" ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                  </Button>
                </div>
                <div className="terminal-output">{gitlabCiYaml}</div>
              </div>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <p className="text-xs font-medium">CLI</p>
                  <Button variant="ghost" size="sm" onClick={() => copyToClipboard(cliCommand, "cli")}>
                    {copiedYaml === "cli" ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                  </Button>
                </div>
                <div className="terminal-output">{cliCommand}</div>
              </div>
              <div className="pt-2 border-t border-border">
                <Button onClick={handleSave} disabled={updateMutation.isPending} size="sm">
                  {updateMutation.isPending ? "Applying..." : "Apply"}
                </Button>
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}