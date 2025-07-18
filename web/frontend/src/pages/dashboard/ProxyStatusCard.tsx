// web/frontend/src/pages/dashboard/ProxyStatusCard.tsx

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { 
    ClipboardCopy, AlertCircle, ServerOff, Timer, ArrowRightLeft, 
    Download, Upload, Loader2, Hourglass, LogIn, LogOut, RefreshCw, MapPin, Tag, Server
} from 'lucide-react';
import { type ProxyDetails } from "@/types/dashboard";
import { toast } from "sonner";
import { useState, useEffect } from "react";
import { cn } from "@/lib/utils";
import React from "react";

// --- Sub-components for better structure and reusability ---

interface StatusSectionProps {
    title: string;
    icon: React.ElementType;
    children: React.ReactNode;
}

/**
 * A reusable section container with a title, icon, and divider.
 */
const StatusSection = ({ title, icon: Icon, children }: StatusSectionProps) => (
    <div className="space-y-3">
        <div className="flex items-center gap-2 text-base font-semibold">
            <Icon className="h-4 w-4 text-muted-foreground" />
            <h4>{title}</h4>
        </div>
        <div className="space-y-2 pl-4 border-l-2 ml-2">
            {children}
        </div>
    </div>
);

interface DetailItemProps {
    label: string;
    icon: React.ElementType;
    children: React.ReactNode;
    onCopy?: () => void;
}

/**
 * A flexible row item for displaying a piece of data with an icon and optional copy button.
 */
const DetailItem = ({ label, icon: Icon, children, onCopy }: DetailItemProps) => {
    if (!children) return null;

    return (
        <div className={cn(
            "flex justify-between items-center text-sm py-1.5 rounded-md",
            onCopy && "hover:bg-muted/50 -ml-2 pl-2 pr-1 group" // Add padding on hover for better visual feedback
        )}>
            <div className="flex items-center gap-2">
                <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                <span className="text-muted-foreground">{label}</span>
            </div>
            <div className="flex items-center gap-2 text-right">
                {children}
                {onCopy && (
                    <Button variant="ghost" size="icon" className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity" onClick={onCopy}>
                        <ClipboardCopy className="h-3.5 w-3.5" />
                    </Button>
                )}
            </div>
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
        const timer = setInterval(() => {
            setTimeLeft(calculateTimeLeft());
        }, 1000);
        return () => clearInterval(timer);
    }, [to]);

    return (
        <span>{String(timeLeft.minutes).padStart(2, '0')}:{String(timeLeft.seconds).padStart(2, '0')}</span>
    );
});


// --- Main Card Component ---

export function ProxyStatusCard({ details }: { details: ProxyDetails | null }) {
    // Empty state when the proxy is stopped
    if (!details) {
        return (
            <Card className="flex flex-col justify-center items-center text-center h-full min-h-[370px]">
                <CardContent className="flex flex-col items-center gap-4">
                    <div className="bg-muted rounded-full p-3 w-fit">
                        <ServerOff className="h-8 w-8 text-muted-foreground" />
                    </div>
                    <div className="space-y-1">
                        <p className="font-semibold">Proxy Service Stopped</p>
                        <p className="text-sm text-muted-foreground">Start the proxy to see live details.</p>
                    </div>
                </CardContent>
            </Card>
        );
    }

    const { inbound, activeOutbound, rotationInterval, rotationStatus, nextRotationTime, totalConfigs } = details;

    const getRotationStatusBadge = () => {
        switch (rotationStatus) {
            case 'testing': return <Badge variant="secondary"><Loader2 className="mr-1.5 h-3 w-3 animate-spin" />Testing</Badge>;
            case 'switching': return <Badge variant="secondary"><ArrowRightLeft className="mr-1.5 h-3 w-3 animate-pulse" />Switching</Badge>;
            case 'stalled': return <Badge variant="destructive"><Hourglass className="mr-1.5 h-3 w-3" />Stalled</Badge>;
            default: return <Badge variant="outline" className="font-mono"><Countdown to={nextRotationTime} /></Badge>;
        }
    };
    
    const handleCopy = (label: string, value: string) => {
        navigator.clipboard.writeText(value).then(() => {
            toast.success(`${label} copied to clipboard!`);
        });
    };

    return (
        <Card>
            <CardHeader>
                <CardTitle>Live Proxy Status</CardTitle>
                <CardDescription>Details of the currently active proxy instance.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
                <StatusSection title="Inbound Listener" icon={LogIn}>
                    <DetailItem icon={Badge} label="Protocol">
                        <span className="font-mono text-xs font-semibold">{inbound.Protocol.toUpperCase()}</span>
                    </DetailItem>
                    <DetailItem icon={Server} label="Address">
                        <span className="font-mono text-xs">{`${inbound.Address}:${inbound.Port}`}</span>
                    </DetailItem>
                    <DetailItem icon={ClipboardCopy} label="Link" onCopy={() => handleCopy('Inbound Link', inbound.OrigLink)}>
                        <span className="font-mono text-xs truncate max-w-[200px] sm:max-w-[250px]">{inbound.OrigLink}</span>
                    </DetailItem>
                </StatusSection>

                <StatusSection title="Active Outbound" icon={LogOut}>
                    {activeOutbound && activeOutbound.protocol ? (
                        <>
                            <DetailItem icon={Tag} label="Remark">
                                <span className="font-mono text-xs truncate max-w-[200px] sm:max-w-xs">{activeOutbound.protocol.remark || 'N/A'}</span>
                            </DetailItem>
                            <DetailItem icon={Timer} label="Delay">
                                <Badge variant="secondary">{activeOutbound.delay}ms</Badge>
                            </DetailItem>
                            <DetailItem icon={Download} label="Download">
                                <span className="font-mono text-xs">{activeOutbound.download > 0 ? `${activeOutbound.download.toFixed(2)} Mbps` : 'N/A'}</span>
                            </DetailItem>
                            <DetailItem icon={Upload} label="Upload">
                                <span className="font-mono text-xs">{activeOutbound.upload > 0 ? `${activeOutbound.upload.toFixed(2)} Mbps` : 'N/A'}</span>
                            </DetailItem>
                             <DetailItem icon={MapPin} label="Location">
                                <span className="font-mono text-xs">{activeOutbound.location !== 'null' ? activeOutbound.location : 'N/A'}</span>
                            </DetailItem>
                            <DetailItem icon={ClipboardCopy} label="Link" onCopy={() => handleCopy('Outbound Link', activeOutbound.link)}>
                                <span className="font-mono text-xs truncate max-w-[200px] sm:max-w-[250px]">{activeOutbound.link}</span>
                            </DetailItem>
                        </>
                    ) : (
                        <div className="flex items-center gap-2 text-muted-foreground text-sm pl-2">
                            <AlertCircle className="h-4 w-4" />
                            <span>No active outbound. Waiting for rotation...</span>
                        </div>
                    )}
                </StatusSection>

                <StatusSection title="Rotation" icon={RefreshCw}>
                    <DetailItem icon={AlertCircle} label="Status">
                        {totalConfigs > 1 ? getRotationStatusBadge() : <Badge variant="outline">Disabled</Badge>}
                    </DetailItem>
                    {totalConfigs > 1 && (
                        <DetailItem icon={Timer} label="Interval">
                           <span className="font-mono text-xs">{rotationInterval}s</span>
                        </DetailItem>
                    )}
                     <DetailItem icon={Server} label="Total Configs">
                        <span className="font-mono text-xs">{totalConfigs}</span>
                    </DetailItem>
                </StatusSection>
            </CardContent>
        </Card>
    );
}