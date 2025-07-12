import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import axios from 'axios';
import { Loader2, Globe } from 'lucide-react';

export function HttpTesterTab() {
    const [httpTestConfigs, setHttpTestConfigs] = useState('');
    const [threadCount, setThreadCount] = useState(50);
    const [maxDelay, setMaxDelay] = useState(5000);
    const [coreType, setCoreType] = useState('auto');
    const [isTesting, setIsTesting] = useState(false);

    const handleRunHttpTest = async () => {
        if (!httpTestConfigs.trim()) {
            toast.error("HTTP Test configurations cannot be empty.");
            return;
        }
        setIsTesting(true);
        toast.info("Starting HTTP configuration test...");
        try {
            const links = httpTestConfigs.trim().split('\n').map(link => link.trim()).filter(link => link);
            await axios.post('/api/v1/http/test', {
                links,
                threadCount,
                maxDelay,
                coreType,
            });
            toast.success("HTTP test initiated. See logs for results.");
        } catch (error) {
            console.error("Failed to start HTTP test:", error);
            toast.error("Failed to start HTTP test.");
        } finally {
            setIsTesting(false);
        }
    };

    return (
        <Card>
            <CardHeader className="flex flex-col">
                <CardTitle>Configuration Tester</CardTitle>
                <CardDescription>Test a list of configurations for latency and speed.</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                    <div className="flex flex-col gap-2">
                        <Label htmlFor="thread-count">Thread Count</Label>
                        <Input
                            id="thread-count"
                            type="number"
                            min={1}
                            max={200}
                            value={threadCount}
                            onChange={(e) => setThreadCount(Math.max(1, parseInt(e.target.value) || 50))}
                        />
                    </div>
                    <div className="flex flex-col gap-2">
                        <Label htmlFor="max-delay">Max Delay (ms)</Label>
                        <Input
                            id="max-delay"
                            type="number"
                            min={1000}
                            max={30000}
                            step={1000}
                            value={maxDelay}
                            onChange={(e) => setMaxDelay(Math.max(1000, parseInt(e.target.value) || 5000))}
                        />
                    </div>
                    <div className="flex flex-col gap-2">
                        <Label htmlFor="core-type">Core Type</Label>
                        <Select value={coreType} onValueChange={setCoreType}>
                            <SelectTrigger id="core-type">
                                <SelectValue placeholder="Select core type" />
                            </SelectTrigger>
                            <SelectContent className="h-full">
                                <SelectItem value="auto">Auto</SelectItem>
                                <SelectItem value="http">xray</SelectItem>
                                <SelectItem value="socks">singbox</SelectItem>
                            </SelectContent>
                        </Select>
                    </div>
                </div>
                <div className="flex flex-col gap-3">
                    <Label htmlFor="http-test-configs">Configuration Links</Label>
                    <Textarea
                        id="http-test-configs"
                        placeholder="Enter config links, one per line..."
                        className="h-40 font-mono text-sm resize-y min-h-[100px]"
                        value={httpTestConfigs}
                        onChange={(e) => setHttpTestConfigs(e.target.value)}
                    />
                </div>

                <Button onClick={handleRunHttpTest} disabled={isTesting}>
                    {isTesting ? (
                        <>
                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                            Testing...
                        </>
                    ) : (
                        <>
                            <Globe className="mr-2 h-4 w-4" />
                            Run Test
                        </>
                    )}
                </Button>
            </CardContent>
        </Card>
    );
}