import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ClipboardCopy, AlertCircle, Info, Timer, ArrowRightLeft, Download, Upload, Loader2, Hourglass } from 'lucide-react';
import { type ProxyDetails } from "@/types/dashboard";
import { toast } from "sonner";
import { useState, useEffect } from "react";

interface ProxyStatusCardProps {
    details: ProxyDetails | null;
}

const DetailRow = ({ label, value, isLink = false }: { label: React.ReactNode; value: React.ReactNode; isLink?: boolean }) => {
    if (!value) return null;

    const handleCopy = () => {
        if (typeof value === 'string' || typeof value === 'number') {
            navigator.clipboard.writeText(String(value)).then(() => {
                toast.success(`${label} copied to clipboard!`);
            });
        }
    };

    return (
        <div className="flex justify-between items-center text-sm">
            <span className="text-muted-foreground">{label}</span>
            <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-right break-all">{value}</span>
                {isLink && (
                    <Button variant="ghost" size="icon" className="h-6 w-6" onClick={handleCopy}>
                        <ClipboardCopy className="h-3.5 w-3.5" />
                    </Button>
                )}
            </div>
        </div>
    );
};

const Countdown = ({ to }: { to: string }) => {
    const calculateTimeLeft = () => {
        const difference = +new Date(to) - +new Date();
        let timeLeft = { minutes: 0, seconds: 0 };
        if (difference > 0) {
            timeLeft = {
                minutes: Math.floor((difference / 1000 / 60) % 60),
                seconds: Math.floor((difference / 1000) % 60),
            };
        }
        return timeLeft;
    };

    const [timeLeft, setTimeLeft] = useState(calculateTimeLeft());

    useEffect(() => {
        const timer = setTimeout(() => {
            setTimeLeft(calculateTimeLeft());
        }, 1000);
        return () => clearTimeout(timer);
    });

    return (
        <span>{String(timeLeft.minutes).padStart(2, '0')}:{String(timeLeft.seconds).padStart(2, '0')}</span>
    );
}

export function ProxyStatusCard({ details }: ProxyStatusCardProps) {
    if (!details) {
        return (
            <Card className="flex flex-col justify-center text-center h-full min-h-[300px]">
                <CardHeader><div className="mx-auto bg-muted rounded-full p-3 w-fit">
                    <Info className="h-8 w-8 text-muted-foreground" /></div></CardHeader>
                <CardContent className="space-y-2">
                    <p className="font-semibold">Proxy Service Stopped</p>
                    <p className="text-sm text-muted-foreground">Start the proxy service to see its live details here.</p>
                </CardContent>
            </Card>
        );
    }

    const { inbound, activeOutbound, rotationInterval, rotationStatus, nextRotationTime, totalConfigs } = details;

    const getRotationStatusBadge = () => {
        switch (rotationStatus) {
            case 'testing': return <Badge variant="secondary"><Loader2 className="mr-1 h-3 w-3 animate-spin" />Testing</Badge>;
            case 'switching': return <Badge variant="secondary"><ArrowRightLeft className="mr-1 h-3 w-3 animate-pulse" />Switching</Badge>;
            case 'stalled': return <Badge variant="destructive"><Hourglass className="mr-1 h-3 w-3" />Stalled</Badge>;
            default: return <Badge variant="outline"><Countdown to={nextRotationTime} /></Badge>;
        }
    };

    return (
        <Card>
            <CardHeader><CardTitle>Live Proxy Status</CardTitle><CardDescription>Details of the currently active proxy instance.</CardDescription></CardHeader>
            <CardContent className="space-y-6">
                <div className="space-y-3">
                    <h4 className="font-semibold text-base">Inbound Listener</h4>
                    <div className="space-y-2 pl-2 border-l-2">
                        <DetailRow label="Protocol" value={inbound.Protocol.toUpperCase()} />
                        <DetailRow label="Listen Address" value={`${inbound.Address}:${inbound.Port}`} />
                        <DetailRow label="Link" value={inbound.OrigLink} isLink />
                    </div>
                </div>

                <div className="space-y-3">
                    <h4 className="font-semibold text-base">Active Outbound</h4>
                    {activeOutbound && activeOutbound.protocol ? (
                        <div className="space-y-2 pl-2 border-l-2">
                            <DetailRow label="Remark" value={activeOutbound.protocol.remark || 'N/A'} />
                            <DetailRow label="Status" value={<><Badge variant="default" className="bg-green-500 text-white hover:bg-green-600 capitalize">{activeOutbound.status}</Badge><Badge variant="secondary"><Timer className="mr-1 h-3 w-3" />{activeOutbound.delay}ms</Badge></>} />
                            <DetailRow label="Speed" value={<><Badge variant="outline"><Download className="mr-1 h-3 w-3" />{activeOutbound.download > 0 ? `${activeOutbound.download.toFixed(2)} Mbps` : 'N/A'}</Badge><Badge variant="outline"><Upload className="mr-1 h-3 w-3" />{activeOutbound.upload > 0 ? `${activeOutbound.upload.toFixed(2)} Mbps` : 'N/A'}</Badge></>} />
                            <DetailRow label="Location" value={activeOutbound.location !== 'null' ? activeOutbound.location : 'N/A'} />
                            <DetailRow label="Link" value={activeOutbound.link} isLink />
                        </div>
                    ) : (
                        <div className="flex items-center gap-2 text-muted-foreground text-sm pl-2"><AlertCircle className="h-4 w-4" /><span>No active outbound. Waiting for rotation...</span></div>
                    )}
                </div>

                <div className="space-y-3">
                    <h4 className="font-semibold text-base">Rotation</h4>
                    <div className="space-y-2 pl-2 border-l-2">
                        <DetailRow label="Status" value={totalConfigs > 1 ? getRotationStatusBadge() : <Badge variant="outline">Disabled</Badge>} />
                        {totalConfigs > 1 && <DetailRow label="Interval" value={`${rotationInterval}s`} />}
                        <DetailRow label="Total Configs" value={totalConfigs} />
                    </div>
                </div>
            </CardContent>
        </Card>
    );
}