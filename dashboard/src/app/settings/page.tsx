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
  const { data: config, isLoading } = useQuery({
    queryKey: ["config"],
    queryFn: getConfig,
  });
  const { data: modules } = useQuery({
    queryKey: ["modules"],
    queryFn: listModules,
  });

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
    const updates: Record<string, unknown> = {
      quality_gate: {
        fail_on_severity: failOn,
        ...(maxFindings ? { max_findings: parseInt(maxFindings) } : {}),
        ...(maxRiskScore ? { max_risk_score: parseInt(maxRiskScore) } : {}),
      },
    };
    updateMutation.mutate(updates);
  };

  const handleModuleToggle = (moduleName: string, enabled: boolean) => {
    updateMutation.mutate({
      modules: {
        [moduleName]: { enabled },
      },
    });
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

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-mono font-bold flex items-center gap-2">
        <Settings className="h-6 w-6" />
        Settings
      </h1>

      {isLoading ? (
        <div className="space-y-4">
          <Skeleton className="h-32 w-full" />
          <Skeleton className="h-48 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      ) : (
        <>
          {/* Quality Gate Config */}
          <Card>
            <CardHeader>
              <CardTitle>Quality Gate</CardTitle>
              <CardDescription>Configure quality gate thresholds</CardDescription>
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

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-mono text-muted-foreground">Max Findings</label>
                  <Input
                    type="number"
                    placeholder="No limit"
                    value={maxFindings}
                    onChange={(e) => setMaxFindings(e.target.value)}
                    className="mt-1"
                  />
                </div>
                <div>
                  <label className="text-sm font-mono text-muted-foreground">Max Risk Score</label>
                  <Input
                    type="number"
                    placeholder="No limit"
                    value={maxRiskScore}
                    onChange={(e) => setMaxRiskScore(e.target.value)}
                    className="mt-1"
                  />
                </div>
              </div>

              <Button onClick={handleSave} disabled={updateMutation.isPending}>
                {updateMutation.isPending ? "Saving..." : "Save Configuration"}
              </Button>
            </CardContent>
          </Card>

          {/* Modules */}
          <Card>
            <CardHeader>
              <CardTitle>Scanner Modules</CardTitle>
              <CardDescription>Available scanning modules</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {(modules ?? []).map((mod) => (
                  <div
                    key={mod.name}
                    className="flex items-center justify-between p-3 rounded-md border border-border"
                  >
                    <div>
                      <p className="text-sm font-mono font-medium">{mod.display_name}</p>
                      <p className="text-xs text-muted-foreground">{mod.category}</p>
                    </div>
                    <button
                      onClick={() => handleModuleToggle(mod.name, !mod.enabled)}
                      className={`px-2 py-1 text-xs rounded cursor-pointer ${
                        mod.enabled ? "bg-primary/20 text-primary" : "bg-muted text-muted-foreground"
                      }`}
                    >
                      {mod.enabled ? "ON" : "OFF"}
                    </button>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* CI/CD Integration */}
          <Card>
            <CardHeader>
              <CardTitle>CI/CD Integration</CardTitle>
              <CardDescription>Copy-paste pipeline configurations</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* GitHub Actions */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-mono font-medium">GitHub Actions</h3>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => copyToClipboard(githubActionsYaml, "github")}
                  >
                    {copiedYaml === "github" ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                  </Button>
                </div>
                <div className="terminal-output text-xs">{githubActionsYaml}</div>
              </div>

              {/* GitLab CI */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-mono font-medium">GitLab CI</h3>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => copyToClipboard(gitlabCiYaml, "gitlab")}
                  >
                    {copiedYaml === "gitlab" ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                  </Button>
                </div>
                <div className="terminal-output text-xs">{gitlabCiYaml}</div>
              </div>

              {/* CLI Command */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-mono font-medium">CLI Command</h3>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => copyToClipboard(cliCommand, "cli")}
                  >
                    {copiedYaml === "cli" ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                  </Button>
                </div>
                <div className="terminal-output text-xs">{cliCommand}</div>
              </div>

              {/* Apply Gate Settings */}
              <div className="pt-2 border-t border-border">
                <Button onClick={handleSave} disabled={updateMutation.isPending}>
                  {updateMutation.isPending ? "Applying..." : "Apply Gate Settings"}
                </Button>
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}