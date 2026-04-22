import { cn } from "@/lib/utils";

interface BadgeProps {
  variant?: "default" | "success" | "destructive" | "warning" | "info" | "outline";
  className?: string;
  children: React.ReactNode;
}

const variantStyles: Record<string, string> = {
  default: "bg-muted text-foreground border-transparent",
  success: "bg-primary/10 text-primary border-transparent",
  destructive: "bg-destructive/10 text-destructive border-transparent",
  warning: "bg-warning/10 text-warning border-transparent",
  info: "bg-info/10 text-info border-transparent",
  outline: "bg-transparent text-muted-foreground border-border",
};

export function Badge({ variant = "default", className, children }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded border px-1.5 py-px text-[11px] font-medium leading-4",
        variantStyles[variant],
        className,
      )}
    >
      {children}
    </span>
  );
}