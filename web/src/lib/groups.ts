export const groupNameCollator = new Intl.Collator(["zh-CN-u-co-pinyin", "en"], {
    numeric: true,
    sensitivity: "base",
});
const namedGroupPriorities: Record<string, number> = {
    优选直连线路: 1,
    "音乐/视频APP专线": 2,
};

function groupPriority(group: string): number {
    const namedPriority = namedGroupPriorities[group];
    if (namedPriority !== undefined) return namedPriority;
    return /➩\s*中国(?:大陆)?$/u.test(group) ? 3 : 0;
}

export function compareGroupNames(left: string, right: string): number {
    return (
        groupPriority(left) - groupPriority(right) ||
        groupNameCollator.compare(left, right)
    );
}
