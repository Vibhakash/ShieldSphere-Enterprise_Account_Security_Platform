import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Ban, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { api, ApiError } from "@/lib/api";
import type { IpBlocklistOut } from "@/lib/types";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";

type BlockDuration = "1h" | "24h" | "7d" | "permanent";

export function BlockIpDialog({
  ipAddress = "",
  defaultReason = "",
  triggerLabel = "Block this IP",
}: {
  ipAddress?: string | null;
  defaultReason?: string;
  triggerLabel?: string;
}) {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [ip, setIp] = useState(ipAddress ?? "");
  const [reason, setReason] = useState(defaultReason);
  const [duration, setDuration] = useState<BlockDuration>("24h");

  const block = useMutation({
    mutationFn: () =>
      api<IpBlocklistOut>("/ip-blocklist", {
        method: "POST",
        body: {
          ip_address: ip.trim(),
          reason: reason.trim(),
          duration,
        },
      }),
    onSuccess: (entry) => {
      toast.success(`${entry.ip_address} is now blocked`);
      setOpen(false);
      queryClient.invalidateQueries({ queryKey: ["blocklist"] });
      queryClient.invalidateQueries({ queryKey: ["dash"] });
      queryClient.invalidateQueries({ queryKey: ["threats"] });
    },
    onError: (error) => {
      toast.error(error instanceof ApiError ? error.message : "Failed to block IP address");
    },
  });

  function handleOpenChange(nextOpen: boolean) {
    setOpen(nextOpen);
    if (nextOpen) {
      setIp(ipAddress ?? "");
      setReason(defaultReason);
      setDuration("24h");
      block.reset();
    }
  }

  const canSubmit = ip.trim().length > 0 && reason.trim().length >= 3 && !block.isPending;

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        <Button size="sm" variant="outline" onClick={(event) => event.stopPropagation()}>
          <Ban className="mr-1 h-3.5 w-3.5" />
          {triggerLabel}
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Block an IP address</DialogTitle>
          <DialogDescription>
            Prevent this address from signing in to your account for the selected duration. Your
            other accounts and platform users are not affected.
          </DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            block.mutate();
          }}
        >
          <div className="space-y-2">
            <Label htmlFor="block-ip-address">IP address</Label>
            <Input
              id="block-ip-address"
              value={ip}
              onChange={(event) => setIp(event.target.value)}
              placeholder="203.0.113.25"
              autoComplete="off"
              required
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="block-ip-reason">Reason</Label>
            <Textarea
              id="block-ip-reason"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder="Example: repeated failed sign-in attempts"
              maxLength={255}
              required
            />
            <p className="text-xs text-muted-foreground">
              This reason is saved in your security audit trail.
            </p>
          </div>
          <div className="space-y-2">
            <Label htmlFor="block-ip-duration">Duration</Label>
            <Select value={duration} onValueChange={(value) => setDuration(value as BlockDuration)}>
              <SelectTrigger id="block-ip-duration">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="1h">1 hour</SelectItem>
                <SelectItem value="24h">24 hours</SelectItem>
                <SelectItem value="7d">7 days</SelectItem>
                <SelectItem value="permanent">Permanent</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" variant="destructive" disabled={!canSubmit}>
              {block.isPending ? (
                <Loader2 className="mr-1 h-4 w-4 animate-spin" />
              ) : (
                <Ban className="mr-1 h-4 w-4" />
              )}
              Block IP
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
