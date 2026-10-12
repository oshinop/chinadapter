import { useEffect, useMemo, useRef, useState } from "react";
import type { NodeRecord } from "@/types";
import { copyText } from "@/lib/clipboard";
import { compareGroupNames, groupNameCollator } from "@/lib/groups";

export function useSubscriptionLink(eligibleNodes: NodeRecord[], subscriptionURL: string) {
    const [copyMessage, setCopyMessage] = useState("");
    const [filterProvider, setFilterProvider] = useState("");
    const [filterGroup, setFilterGroup] = useState("");
    const [filterName, setFilterName] = useState("");
    const copyResetTimer = useRef<number | undefined>(undefined);

    const nodeProviders = useMemo(
        () =>
            [...new Set(eligibleNodes.map((node) => node.provider))].sort(
                groupNameCollator.compare,
            ),
        [eligibleNodes],
    );
    const filterGroups = useMemo(
        () =>
            [
                ...new Set(
                    eligibleNodes
                        .filter(
                            (node) =>
                                !filterProvider ||
                                node.provider === filterProvider,
                        )
                        .map((node) => node.group),
                ),
            ].sort(compareGroupNames),
        [eligibleNodes, filterProvider],
    );

    useEffect(() => {
        if (filterGroup && !filterGroups.includes(filterGroup))
            setFilterGroup("");
    }, [filterGroup, filterGroups]);

    const filteredSubscriptionURL = useMemo(() => {
        if (!subscriptionURL) return "";
        try {
            const next = new URL(subscriptionURL);
            if (filterProvider)
                next.searchParams.set("provider", filterProvider);
            if (filterGroup) next.searchParams.set("group", filterGroup);
            if (filterName.trim())
                next.searchParams.set("name", filterName.trim());
            return next.toString();
        } catch {
            return subscriptionURL;
        }
    }, [filterGroup, filterName, filterProvider, subscriptionURL]);

    const clearCopyMessage = () => {
        clearTimeout(copyResetTimer.current);
        copyResetTimer.current = undefined;
        setCopyMessage("");
    };

    useEffect(() => () => clearTimeout(copyResetTimer.current), []);
    useEffect(() => {
        clearCopyMessage();
    }, [filteredSubscriptionURL]);

    const copySubscription = async () => {
        if (!filteredSubscriptionURL) return;
        clearCopyMessage();
        setCopyMessage(
            (await copyText(filteredSubscriptionURL))
                ? "Link copied."
                : "Copy is unavailable.",
        );
        copyResetTimer.current = window.setTimeout(
            () => setCopyMessage(""),
            2500,
        );
    };

    const resetFilters = () => {
        clearCopyMessage();
        setFilterProvider("");
        setFilterGroup("");
        setFilterName("");
    };

    return {
        copyMessage,
        copySubscription,
        filterGroup,
        filterGroups,
        filterName,
        filterProvider,
        filteredSubscriptionURL,
        nodeProviders,
        resetFilters,
        setFilterGroup,
        setFilterName,
        setFilterProvider,
    };
}
