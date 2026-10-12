import { Copy } from "lucide-react";
import { Field, selectClassName } from "@/components/forms";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { providerLabel } from "@/features/accounts/providers";
import type { useSubscriptionLink } from "./useSubscriptionLink";

export function SubscriptionLinkCard({ link }: { link: ReturnType<typeof useSubscriptionLink> }) {
    const {
        copyMessage,
        copySubscription,
        filterGroup,
        filterGroups,
        filterName,
        filterProvider,
        filteredSubscriptionURL,
        nodeProviders,
        setFilterGroup,
        setFilterName,
        setFilterProvider,
    } = link;

    return (
        <Card className="panel">
            <CardHeader>
                <CardTitle>Subscription link</CardTitle>
                <CardAction>
                    <Tooltip>
                        <TooltipTrigger asChild>
                            <Button
                                aria-label="Copy subscription link"
                                disabled={
                                    !filteredSubscriptionURL
                                }
                                onClick={() =>
                                    void copySubscription()
                                }
                                size="icon"
                                variant="ghost"
                            >
                                <Copy className="size-4" />
                            </Button>
                        </TooltipTrigger>
                        <TooltipContent>
                            Copy filtered link
                        </TooltipContent>
                    </Tooltip>
                </CardAction>
            </CardHeader>
            <CardContent className="grid gap-3">
                <div className="grid gap-3 sm:grid-cols-3">
                    <Field
                        label="Provider"
                        name="subscription-provider"
                    >
                        <select
                            className={selectClassName}
                            id="subscription-provider"
                            onChange={(event) =>
                                setFilterProvider(
                                    event.currentTarget.value,
                                )
                            }
                            value={filterProvider}
                        >
                            <option value="">
                                All providers
                            </option>
                            {nodeProviders.map((provider) => (
                                <option
                                    key={provider}
                                    value={provider}
                                >
                                    {providerLabel(provider)}
                                </option>
                            ))}
                        </select>
                    </Field>
                    <Field
                        label="Group"
                        name="subscription-group"
                    >
                        <select
                            className={selectClassName}
                            id="subscription-group"
                            onChange={(event) =>
                                setFilterGroup(
                                    event.currentTarget.value,
                                )
                            }
                            value={filterGroup}
                        >
                            <option value="">All groups</option>
                            {filterGroups.map((group) => (
                                <option
                                    key={group}
                                    value={group}
                                >
                                    {group}
                                </option>
                            ))}
                        </select>
                    </Field>
                    <Field
                        label="Node name"
                        name="subscription-name"
                    >
                        <Input
                            id="subscription-name"
                            onChange={(event) =>
                                setFilterName(
                                    event.currentTarget.value,
                                )
                            }
                            placeholder="Contains…"
                            value={filterName}
                        />
                    </Field>
                </div>
                <code
                    aria-busy={!filteredSubscriptionURL}
                    className="readout block break-all rounded-sm border border-border/70 px-3 py-2.5 text-xs leading-5 text-primary/90"
                >
                    {filteredSubscriptionURL || (
                        <span className="animate-pulse text-muted-foreground">
                            Loading link…
                        </span>
                    )}
                </code>
                <p
                    aria-live="polite"
                    className="min-h-5 text-xs text-muted-foreground"
                    role="status"
                >
                    {copyMessage}
                </p>
            </CardContent>
        </Card>
    );
}
