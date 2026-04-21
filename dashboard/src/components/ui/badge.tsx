import { cn } from "@/lib/utils";

interface BadgeProps {
  variant?: "default" | "success" | "destructive" | "warning" | "info" | "outline";
  className?: string;
  children: React.ReactNode;
}

const variantStyles: Record<string, string> = {
  default: "bg-muted text-foreground border-border",
  success: "bg-primary/20 text-primary border-primary/30",
  destructive: "bg-destructive/20 text-destructive border-destructive/30",
  warning: "bg-warning/20 text-warning border-warning/30",
  info: "bg-info/20 text-info border-info/30",
  outline: "bg-transparent text-foreground border-border",
};

export function Badge({ variant = "default", className, children }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium font-mono",
        variantStyles[variant],
        className,
      )}
    >
      {children}
    </span>
  );
}