import logo from "@/assets/ldot-logo.png";
import { cn } from "@/lib/utils";

interface BrandMarkProps {
  className?: string;
  size?: number;
  /** Show on dark backgrounds — inverts the black glyph to white. */
  invert?: boolean;
}

export function BrandMark({ className, size = 36, invert = false }: BrandMarkProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center justify-center overflow-hidden rounded-lg bg-background",
        className,
      )}
      style={{ width: size, height: size }}
      aria-label="LDOT"
    >
      <img
        src={logo}
        alt=""
        width={size}
        height={size}
        className={cn("h-full w-full object-contain", invert && "invert")}
        draggable={false}
      />
    </span>
  );
}
