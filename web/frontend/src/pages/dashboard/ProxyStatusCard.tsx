import React, { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { 
    ClipboardCopy, AlertCircle, ServerOff, Timer, ArrowRightLeft, 
    LogIn, LogOut, RefreshCw, MapPin, Tag, Server, Download, Upload, Hourglass, Loader2
} from 'lucide-react';
import { type ProxyDetails } from "@/types/dashboard";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

// --- Sub-components for the new design ---

interface DetailItemProps {
    label: string;
    icon: React.ElementType;
    children: React.ReactNode;
    onCopy?: () => void;
    className?: string;
}

/**
 * A compact, flexible row item for displaying a piece of data.
 */
const DetailItem = ({ label, icon: Icon, children, onCopy, className }: DetailItemProps) => {
    if (!children) return null;
    const content = (
        <div className={cn("text-sm font-medium", onCopy ? "truncate" : "")}>
            {children}
        </div>
    );

    return (
        <div className={cn("flex items-center justify-between group", className)}>
            <div className="flex items-center gap-2">
                <Icon className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm text-muted-foreground">{label}</span>
            </div>
            {onCopy ? (
                <div className="flex items-center gap-1 min-w-0">
                    <div className="truncate">{content}</div>
                    <Button variant="ghost" size="icon" className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity" onClick={onCopy}>
                        <ClipboardCopy className="h-3.5 w-3.5" />
                    </Button>
                </div>
            ) : (
                content
            )}
        </div>
    );
};

/**
 * A memoized countdown timer to prevent unnecessary re-renders.
 */
const Countdown = React.memo(({ to }: { to: string }) => {
    const calculateTimeLeft = () => {
        const difference = +new Date(to) - +new Date();
        if (difference <= 0) return { minutes: 0, seconds: 0 };
        return {
            minutes: Math.floor((difference / 1000 / 60) % 60),
            seconds: Math.floor((difference / 1000) % 60),
        };
    };

    const [timeLeft, setTimeLeft] = useState(calculateTimeLeft());

    useEffect(() => {
        const timer = setInterval(() => setTimeLeft(calculateTimeLeft()), 1000);
        return () => clearInterval(timer);
    }, [to]);

    return (
        <span className="font-mono text-sm">{String(timeLeft.minutes).padStart(2, '0')}:{String(timeLeft.seconds).padStart(2, '0')}</span>
    );
});


// --- Main Card Component ---

export function ProxyStatusCard({ details }: { details: ProxyDetails | null }) {
    if (!details) {
        return (
            <Card className="w-full">
                <CardHeader>
                    <CardTitle>Live Proxy Status</CardTitle>
                    <CardDescription>Details of the currently active proxy instance.</CardDescription>
                </CardHeader>
                <CardContent className="flex flex-col justify-center items-center text-center py-12">
                    <div className="bg-muted rounded-full p-3 w-fit mb-4">
                        <ServerOff className="h-8 w-8 text-muted-foreground" />
                    </div>
                    <p className="font-semibold">Proxy Service Stopped</p>
                    <p className="text-sm text-muted-foreground">Start the proxy to see live details.</p>
                </CardContent>
            </Card>
        );
    }

    const { inbound, activeOutbound, rotationInterval, rotationStatus, nextRotationTime, totalConfigs } = details;
    const handleCopy = (label: string, value: string) => navigator.clipboard.writeText(value).then(() => toast.success(`${label} copied!`));
    
    const getRotationStatusBadge = () => {
        switch (rotationStatus) {
            case 'testing': return <Badge variant="secondary" className="bg-blue-500/20 text-blue-400 border-blue-500/30"><Loader2 className="mr-1.5 h-3 w-3 animate-spin" />Testing</Badge>;
            case 'switching': return <Badge variant="secondary" className="bg-purple-500/20 text-purple-400 border-purple-500/30"><ArrowRightLeft className="mr-1.5 h-3 w-3 animate-pulse" />Switching</Badge>;
            case 'stalled': return <Badge variant="destructive" className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30"><Hourglass className="mr-1.5 h-3 w-3" />Stalled</Badge>;
            default: return <Badge variant="outline"><Countdown to={nextRotationTime} /></Badge>;
        }
    };

    return (
        <Card>
            <CardHeader>
                <CardTitle>Live Proxy Status</CardTitle>
                <CardDescription>Details of the currently active proxy instance.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-4 border rounded-lg p-4">
                    {/* Inbound Section */}
                    <div className="space-y-3">
                        <div className="flex items-center gap-2 font-semibold text-base"><LogIn className="size-4 text-muted-foreground" /><span>Inbound Listener</span></div>
                        <div className="space-y-2 pl-6">
                             <DetailItem icon={Badge} label="Protocol"><span className="font-mono text-xs font-bold">{inbound.Protocol.toUpperCase()}</span></DetailItem>
                            <DetailItem icon={Server} label="Address"><span className="font-mono text-xs">{`${inbound.Address}:${inbound.Port}`}</span></DetailItem>
                            <DetailItem icon={ClipboardCopy} label="Link" onCopy={() => handleCopy('Inbound Link', inbound.OrigLink)}>
                                <span className="font-mono text-xs">{inbound.OrigLink}</span>
                            </DetailItem>
                        </div>
                    </div>

                    {/* Outbound Section */}
                    <div className="space-y-3 md:border-l md:pl-6 -ml-2 md:-ml-0">
                         <div className="flex items-center gap-2 font-semibold text-base"><LogOut className="size-4 text-muted-foreground" /><span>Active Outbound</span></div>
                        {activeOutbound && activeOutbound.protocol ? (
                            <div className="space-y-2 pl-6">
                                <DetailItem icon={Tag} label="Remark"><span className="font-mono text-xs truncate max-w-[150px]">{activeOutbound.protocol.remark || 'N/A'}</span></DetailItem>
                                <DetailItem icon={MapPin} label="Location"><span className="font-mono text-xs">{activeOutbound.location !== 'null' ? activeOutbound.location : 'N/A'}</span></DetailItem>
                                <DetailItem icon={Timer} label="Delay"><Badge variant="secondary">{activeOutbound.delay}ms</Badge></DetailItem>
                                <DetailItem icon={Download} label="Download"><span className="font-mono text-xs">{activeOutbound.download > 0 ? `${activeOutbound.download.toFixed(2)} Mbps` : 'N/A'}</span></DetailItem>
                                <DetailItem icon={Upload} label="Upload"><span className="font-mono text-xs">{activeOutbound.upload > 0 ? `${activeOutbound.upload.toFixed(2)} Mbps` : 'N/A'}</span></DetailItem>
                            </div>
                        ) : (
                            <div className="flex items-center gap-2 text-muted-foreground text-sm pl-6 h-full">
                                <AlertCircle className="h-4 w-4" />
                                <span>Waiting for first active config...</span>
                            </div>
                        )}
                    </div>
                </div>
                 {/* Rotation Section */}
                 <div className="border rounded-lg p-4 space-y-3">
                    <div className="flex items-center gap-2 font-semibold text-base"><RefreshCw className="size-4 text-muted-foreground" /><span>Rotation</span></div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-x-6 gap-y-2 pl-6">
                        <DetailItem icon={AlertCircle} label="Status">{totalConfigs > 1 ? getRotationStatusBadge() : <Badge variant="outline">Disabled</Badge>}</DetailItem>
                        {totalConfigs > 1 && <DetailItem icon={Timer} label="Interval"><span className="font-mono text-xs">{rotationInterval}s</span></DetailItem>}
                        <DetailItem icon={Server} label="Total Configs"><span className="font-mono text-xs">{totalConfigs}</span></DetailItem>
                    </div>
                </div>
            </CardContent>
        </Card>
    );
}